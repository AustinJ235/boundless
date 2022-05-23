pub mod client;
pub mod server;

pub use self::client::SecureSocketClient;
pub use self::server::SecureSocketServer;

use crate::host_keys::HostKeys;
use blake3::{hash, Hash};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use k256::ecdh::EphemeralSecret;
use k256::{EncodedPoint, PublicKey};
use rand::rngs::OsRng;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use strum::FromRepr;

pub type HostID = Hash;
pub type SSSRecvFn = Box<dyn FnMut(&Arc<SecureSocketServer>, HostID, Vec<u8>) + Send>;
pub type SSSOnConnect = Box<dyn FnMut(&Arc<SecureSocketServer>, HostID) + Send>;
pub type SSSOnDisconnect = Box<dyn FnMut(&Arc<SecureSocketServer>, HostID) + Send>;
pub type SSCRecvFn = Box<dyn FnMut(&Arc<SecureSocketClient>, Vec<u8>) + Send>;
pub type SSCOnConnect = Box<dyn FnMut(&Arc<SecureSocketClient>) + Send>;
pub type SSCOnDisconnect = Box<dyn FnMut(&Arc<SecureSocketClient>) + Send>;

// Interval at which the client sends pings.
const PING_INTERVAL: Duration = Duration::from_secs(3);
// Max duration from previous ping before server disconnects client.
const PING_DISCONNECT: Duration = Duration::from_secs(6);
// Max duration from start of handshake before server disconnects client.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
// Interval at which the client does a handshake.
const HANDSHAKE_INTERVAL: Duration = Duration::from_secs(150);
// Max duration from last handshake before the server disconnects client.
const HANDSHAKE_DISCONNECT: Duration = Duration::from_secs(180);
// How many nonces of late packets to keep.
const PREV_NONCE_WINDOW: usize = 15;
// Max encrypted payload size. (UDP max payload - 43B)
const MAX_ENCRYPTED_PAYLOAD: usize = 65464;
// Interval to check clients (connection idle & handshake lifetime)
const CLIENTS_CHECK_INTERVAL: Duration = Duration::from_secs(2);

#[derive(FromRepr, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum PacketType {
	ECDH,
	Verify,
	Ping,
	Message,
}

// ECDH
// ... header ...
//   1B: PacketType
//  32B: Host ID
//   1B: Signature Length
// ~70B: Signature
// ... message ...
//   1B: DH Public Key Length
// ~32B: DH Public Key
// ~32B: Random (fill msg to 64 bytes)

// Rest of messages
// ... header ...
// [0..1]: PacketType
// [1..33]: Host ID
// [33..41]: Sequence
// ... encrypted message ...
// [41..]: Payload (72B+ Message / 16B Tag)
// ... message ...
// [0..8]: Message length
// [8..]: Data

fn hash_slices(inputs: &[&[u8]]) -> Hash {
	let mut hasher = blake3::Hasher::new();

	for input in inputs {
		hasher.update(input);
	}

	hasher.finalize()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
	NotConnected,
	NotVerified,
	Encryption,
	TooLarge,
	SocketError(std::io::ErrorKind),
}

impl std::fmt::Display for SendError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			Self::NotConnected => write!(f, "connection not established"),
			Self::NotVerified => write!(f, "connection not verified"),
			Self::Encryption => write!(f, "packet encrypt failed"),
			Self::TooLarge => write!(f, "packet data would be truncated"),
			Self::SocketError(e) => write!(f, "socket error: {}", e),
		}
	}
}

impl From<CryptoError> for SendError {
	fn from(e: CryptoError) -> Self {
		match e {
			CryptoError::LateOrDup => unreachable!(),
			CryptoError::Decryption => unreachable!(),
			CryptoError::Encryption => Self::Encryption,
			CryptoError::Truncated => Self::TooLarge,
		}
	}
}

impl From<std::io::Error> for SendError {
	fn from(e: std::io::Error) -> Self {
		Self::SocketError(e.kind())
	}
}

struct ECDHSnd {
	secret: EphemeralSecret,
	random: Vec<u8>,
	packet: Vec<u8>,
}

impl ECDHSnd {
	fn new(host_keys: &HostKeys) -> Self {
		let secret = EphemeralSecret::random(&mut OsRng);
		let public = EncodedPoint::from(secret.public_key());

		let mut msg = Vec::with_capacity(64);
		msg.push(0);
		msg.extend_from_slice(public.as_bytes());
		msg[0] = (msg.len() - 1) as u8;

		let mut random = vec![0_u8; 64 - msg.len()];
		OsRng::fill(&mut OsRng, random.as_mut_slice());
		msg.extend_from_slice(&random);

		let mut packet = Vec::with_capacity(170);
		packet.push(PacketType::ECDH as u8);
		packet.extend_from_slice(host_keys.id().as_bytes());
		packet.push(0);
		packet.append(&mut host_keys.sign_message(&msg));
		packet[33] = (packet.len() - 34) as u8;
		packet.append(&mut msg);

		Self {
			secret,
			random,
			packet,
		}
	}

	fn handshake(self, host_keys: &HostKeys, rcv: ECDHRcv) -> CryptoState {
		let secret = hash(self.secret.diffie_hellman(&rcv.public).as_bytes().as_slice());

		CryptoState {
			cipher: ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(secret.as_bytes())),
			nonce_rng_snd: ChaCha20Rng::from_seed(
				hash_slices(&[
					&host_keys.public_key().to_bytes(),
					self.random.as_slice(),
					&host_keys.public_key_of(rcv.hid).unwrap().to_bytes(),
					rcv.random.as_slice(),
					secret.as_bytes(),
				])
				.into(),
			),
			nonce_rng_rcv: ChaCha20Rng::from_seed(
				hash_slices(&[
					&host_keys.public_key_of(rcv.hid).unwrap().to_bytes(),
					rcv.random.as_slice(),
					&host_keys.public_key().to_bytes(),
					self.random.as_slice(),
					secret.as_bytes(),
				])
				.into(),
			),
			seq_snd: 0,
			seq_rcv: 0,
			nonce_previous: HashMap::new(),
		}
	}
}

struct ECDHRcv {
	hid: HostID,
	public: PublicKey,
	random: Vec<u8>,
}

impl ECDHRcv {
	fn new(host_keys: &HostKeys, buffer: &[u8]) -> Result<Self, String> {
		if buffer.len() < 34 {
			return Err(String::from("host-id truncated"));
		}

		let hid_b: [u8; 32] = buffer[1..33].try_into().unwrap();
		let hid = HostID::from(hid_b);
		let signature_len = buffer[33] as usize;
		let signature_end = 34 + signature_len;

		if signature_end > buffer.len() {
			return Err(String::from("signature truncated"));
		}

		let signature_b = &buffer[34..signature_end];
		let message_end = signature_end + 64;

		if message_end > buffer.len() {
			return Err(String::from("message truncated"));
		}

		let message_b = &buffer[signature_end..message_end];
		host_keys.verify_message(hid, signature_b, message_b)?;
		let public_len = message_b[0] as usize;

		if public_len > 63 {
			return Err(String::from("public-key truncated"));
		}

		let public = PublicKey::from_sec1_bytes(&message_b[1..(1 + public_len)])
			.map_err(|_| String::from("public-key invalid"))?;
		let random = message_b[(1 + public_len)..64].to_vec();

		Ok(ECDHRcv {
			hid,
			public,
			random,
		})
	}
}

struct CryptoState {
	cipher: ChaCha20Poly1305,
	nonce_rng_snd: ChaCha20Rng,
	nonce_rng_rcv: ChaCha20Rng,
	seq_snd: u64,
	seq_rcv: u64,
	nonce_previous: HashMap<u64, Nonce>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CryptoError {
	LateOrDup,
	Decryption,
	Encryption,
	Truncated,
}

impl std::fmt::Display for CryptoError {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		match self {
			Self::LateOrDup => write!(f, "packet is either late or a duplicate"),
			Self::Decryption => write!(f, "packet decrypt failed"),
			Self::Encryption => write!(f, "packet encrypt failed"),
			Self::Truncated => write!(f, "packet data is/would be truncated"),
		}
	}
}

impl CryptoState {
	fn decrypt(&mut self, seq: u64, encrypted: &[u8]) -> Result<Vec<u8>, CryptoError> {
		let nonce = if seq < self.seq_rcv {
			match self.nonce_previous.remove(&seq) {
				Some(nonce) => nonce,
				None => return Err(CryptoError::LateOrDup),
			}
		} else if seq > self.seq_rcv {
			let late_seq_start = if seq - self.seq_rcv > PREV_NONCE_WINDOW as u64 {
				self.nonce_previous.clear();
				seq - PREV_NONCE_WINDOW as u64
			} else {
				self.seq_rcv
			};

			for late_seq in self.seq_rcv..seq {
				let mut nonce_b = [0_u8; 12];
				self.nonce_rng_rcv.fill_bytes(&mut nonce_b);

				if late_seq >= late_seq_start {
					self.nonce_previous.insert(late_seq, Nonce::from(nonce_b));
				}

				self.seq_rcv += 1;
			}

			if self.nonce_previous.len() > PREV_NONCE_WINDOW {
				let remove_amt = self.nonce_previous.len() - PREV_NONCE_WINDOW;
				let mut keys: Vec<u64> = self.nonce_previous.keys().cloned().collect();
				keys.sort_unstable();

				for (_, key) in (0..remove_amt).into_iter().zip(keys.into_iter()) {
					self.nonce_previous.remove(&key);
				}
			}

			let mut nonce_b = [0_u8; 12];
			self.nonce_rng_rcv.fill_bytes(&mut nonce_b);
			assert!(self.seq_rcv == seq);
			self.seq_rcv += 1;
			Nonce::from(nonce_b)
		} else {
			let mut nonce_b = [0_u8; 12];
			self.nonce_rng_rcv.fill_bytes(&mut nonce_b);
			self.seq_rcv += 1;
			Nonce::from(nonce_b)
		};

		let decrypted = self.cipher.decrypt(&nonce, encrypted).map_err(|_| CryptoError::Decryption)?;

		if decrypted.len() < 66 {
			return Err(CryptoError::Truncated);
		}

		let msg_len_b: [u8; 2] = decrypted[0..2].try_into().unwrap();
		let msg_len = u16::from_le_bytes(msg_len_b) as usize;

		if msg_len > decrypted.len() + 2 {
			return Err(CryptoError::Truncated);
		}

		Ok(decrypted[2..(2 + msg_len)].to_vec())
	}

	fn encrypt(&mut self, mut data: Vec<u8>) -> Result<(u64, Vec<u8>), CryptoError> {
		let seq = self.seq_snd;
		self.seq_snd += 1;
		let mut nonce_b = [0_u8; 12];
		self.nonce_rng_snd.fill_bytes(&mut nonce_b);
		let nonce = Nonce::from(nonce_b);
		let msg_len = data.len();

		if msg_len > MAX_ENCRYPTED_PAYLOAD {
			return Err(CryptoError::Truncated);
		}

		let mut decrypted = Vec::with_capacity(66);
		decrypted.extend_from_slice(&(msg_len as u16).to_le_bytes());
		decrypted.append(&mut data);

		if msg_len < 64 {
			let mut padding = vec![0_u8; 66 - msg_len];
			OsRng::fill(&mut OsRng, padding.as_mut_slice());
			decrypted.append(&mut padding);
		}

		let encrypted = self.cipher.encrypt(&nonce, decrypted.as_slice()).map_err(|_| CryptoError::Encryption)?;
		Ok((seq, encrypted))
	}
}

#[test]
fn test() {
	use std::thread;

	let mut s_host_keys = HostKeys::generate();
	let mut c_host_keys = HostKeys::generate();
	s_host_keys.trust(c_host_keys.enc_public_key()).unwrap();
	c_host_keys.trust(s_host_keys.enc_public_key()).unwrap();

	let s_thrd_h = thread::spawn(move || {
		let server = SecureSocketServer::listen(
			s_host_keys,
			"0.0.0.0:1026",
			Box::new(move |_host, _client_uid, _packet_data| {}),
			Box::new(move |_host, _client_uid| {}),
			Box::new(move |_host, _client_uid| {}),
		)
		.unwrap();

		server.wait_for_exit().unwrap();
	});

	let c_thrd_h = thread::spawn(move || {
		let client = SecureSocketClient::connect(
			c_host_keys,
			"127.0.0.1:1026",
			Box::new(move |_client, _packet_data| {}),
			Box::new(move |_client| {}),
			Box::new(move |_client| {}),
		)
		.unwrap();

		client.wait_for_conn(Some(HANDSHAKE_TIMEOUT.clone()));
		client.wait_for_exit().unwrap();
	});

	s_thrd_h.join().unwrap();
	c_thrd_h.join().unwrap();
}
