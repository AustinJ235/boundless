/*
Client Handshake Request
  1B: PacketType (1),
 32B: Host ID
  1B: Signature End
~70B: Signature
....: Begin Signed Message
 16B: Handshake ID
  1B: Public Key End (Relative to Signed)
~32B: Public Key
~15B: Random (Fill Signed Message to 64 Bytes)

Client Encrypted Handshake Request
  1B: PacketType (2)
 32B: Host ID
 16B: Previous Handshake ID
  8B: Sequence
....: Begin Encrypted Message
  1B: Signature End (Relative to Encrypted)
~70B: Signature
....: Begin Signed & Encrypted
 16B: Handshake ID
  1B: Public Key End (Relative to Signed)
~32B: Public Key
~15B: Random (Fill Signed Message to 64 Bytes)

Server Handshake Response
  1B: PacketType (3)
 32B: Host ID
  1B: Signature End
~70B: Signature
....: Begin Signed Message
 16B: Handshake ID
  1B: Public Key End (Relative to Signed)
~32B: Public Key
....: Begin Signed & Encrypted
 32B: Hash of Test
 32B: Test (Random Bytes)

Server Encrypted Handshake Response
  1B: PacketType (4)
 32B: Host ID
 16B: Previous Handshake ID
  8B: Sequence
....: Begin Encrypted Message
  1B: Signature End (Relative to Encrypted)
~70B: Signature
....: Begin Signed & Encrypted
 16B: Handshake ID
  1B: Publick Key End (Relative to Signed)
~32B: Public Key
....: Begin Encrypted, Signed, & Encrypted
 32B: Hash of Test
 32B: Test (Random Bytes)

Ping
  1B: PacketType (5)
 32B: Host ID
 16B: Handshake ID
  8B: Sequence
....: Begin Encrypted message
 32B: Hash of Test
 32B: Test (Random Bytes)

Message
  1B: PacketType (6)
 32B: HostID
 16B: Handshake ID
  8B: Sequence
....: Begin Encrypted Message
  2B: Message Length
62<=: Message
*/

use crate::host_keys::HostKeys;
use blake3::{hash, Hash};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use k256::ecdh::EphemeralSecret;
use k256::ecdsa::VerifyingKey;
use k256::{EncodedPoint, PublicKey};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use std::{fmt, io};

pub type HostID = Hash;
pub type HandshakeID = [u8; 16];
pub type OnReceiveFn = Box<dyn FnMut(&Arc<SecureSocket>, HostID, Vec<u8>) + Send>;
pub type OnConnectFn = Box<dyn FnMut(&Arc<SecureSocket>, HostID) + Send>;
pub type OnDisconnectFn = Box<dyn FnMut(&Arc<SecureSocket>, HostID) + Send>;

// Used as peer_id when operating as client in HashMap<HostID, Peer>
const ZERO_HOST_ID: [u8; 32] = [0; 32];
// How often to run peer checks
const CHECK_UP_INTERVAL: Duration = Duration::from_secs(1);
// Max encrypted payload size. (UDP max payload - 256B)
const MAX_ENCRYPTED_PAYLOAD: usize = 65251;
// How many nonces of late packets to keep.
const PREV_NONCE_WINDOW: usize = 15;
// Interval at which the client sends pings.
const PING_INTERVAL: Duration = Duration::from_secs(3);
// Max duration from previous ping before a disconnect occurs.
const PING_DISCONNECT: Duration = Duration::from_secs(6);
// Max duration from start of handshake before a disconnect occurs.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
// Interval at which the client does a handshake.
const HANDSHAKE_INTERVAL: Duration = Duration::from_secs(120);
// Max duration from last handshake before the a disconnect occurs.
const HANDSHAKE_DISCONNECT: Duration = Duration::from_secs(180);

pub struct SecureSocket {
	keys: HostKeys,
	mode: Mode,
	peer: Mutex<HashMap<HostID, Peer>>,
	udp_socket: Arc<UdpSocket>,
	recv_thrd_h: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
	Server,
	Client,
}

impl fmt::Display for Mode {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::Server => write!(f, "Server"),
			Self::Client => write!(f, "Client"),
		}
	}
}

enum ModeDependant {
	Server {
		ping_recv: Instant,
	},
	Client {
		ping_sent: Instant,
		ping_recv: Instant,
		hdshk_sent: Instant,
		peer_id: Option<HostID>,
		hdshk_priv: Option<(HandshakeID, EphemeralSecret)>,
	},
}

struct Peer {
	addr: SocketAddr,
	crypto: HashMap<HandshakeID, Crypto>,
	mode_dep: ModeDependant,
}

impl Peer {
	fn set_ping_recv(&mut self) {
		match &mut self.mode_dep {
			ModeDependant::Server {
				ping_recv,
			} => *ping_recv = Instant::now(),
			ModeDependant::Client {
				ping_recv,
				..
			} => *ping_recv = Instant::now(),
		}
	}

	fn last_ping_recv(&self) -> Instant {
		match &self.mode_dep {
			ModeDependant::Server {
				ping_recv,
			} => ping_recv.clone(),
			ModeDependant::Client {
				ping_recv,
				..
			} => ping_recv.clone(),
		}
	}

	fn set_ping_sent(&mut self) {
		match &mut self.mode_dep {
			ModeDependant::Server {
				..
			} => unreachable!(),
			ModeDependant::Client {
				ping_sent,
				..
			} => *ping_sent = Instant::now(),
		}
	}

	fn last_ping_sent(&self) -> Instant {
		match &self.mode_dep {
			ModeDependant::Server {
				..
			} => unreachable!(),
			ModeDependant::Client {
				ping_sent,
				..
			} => ping_sent.clone(),
		}
	}

	fn cur_peer_id(&self) -> Option<HostID> {
		match &self.mode_dep {
			ModeDependant::Server {
				..
			} => unreachable!(),
			ModeDependant::Client {
				peer_id,
				..
			} => peer_id.clone(),
		}
	}

	fn set_peer_id(&mut self, id: Option<HostID>) {
		match &mut self.mode_dep {
			ModeDependant::Server {
				..
			} => unreachable!(),
			ModeDependant::Client {
				peer_id,
				..
			} => *peer_id = id,
		}
	}

	fn take_peer_id(&mut self) -> Option<HostID> {
		match &mut self.mode_dep {
			ModeDependant::Server {
				..
			} => unreachable!(),
			ModeDependant::Client {
				peer_id,
				..
			} => peer_id.take(),
		}
	}

	fn last_hdshk_recv(&self) -> Option<Instant> {
		let mut negotiated_insts: Vec<_> = self.crypto.values().map(|crypto| &crypto.negotiated).collect();
		negotiated_insts.sort();
		negotiated_insts.last().map(|inst| (*inst).clone())
	}

	fn latest_crypto(&mut self) -> Option<(&HandshakeID, &mut Crypto)> {
		let mut sort_by_latest: Vec<_> = self.crypto.iter_mut().collect();
		sort_by_latest.sort_by_key(|(_, crypto)| crypto.negotiated);
		sort_by_latest.pop()
	}

	fn set_hdshk_sent(&mut self) {
		match &mut self.mode_dep {
			ModeDependant::Server {
				..
			} => unreachable!(),
			ModeDependant::Client {
				hdshk_sent,
				..
			} => *hdshk_sent = Instant::now(),
		}
	}

	fn last_hdshk_sent(&self) -> Instant {
		match &self.mode_dep {
			ModeDependant::Server {
				..
			} => unreachable!(),
			ModeDependant::Client {
				hdshk_sent,
				..
			} => hdshk_sent.clone(),
		}
	}

	fn hdshk_pending(&self) -> bool {
		match &self.mode_dep {
			ModeDependant::Server {
				..
			} => unreachable!(),
			ModeDependant::Client {
				hdshk_priv,
				..
			} => hdshk_priv.is_some(),
		}
	}

	fn take_hdshk_priv(&mut self, id: HandshakeID) -> Option<EphemeralSecret> {
		match &mut self.mode_dep {
			ModeDependant::Server {
				..
			} => unreachable!(),
			ModeDependant::Client {
				hdshk_priv,
				..
			} =>
				if hdshk_priv.is_none() {
					None
				} else if hdshk_priv.as_ref().unwrap().0 != id {
					None
				} else {
					Some(hdshk_priv.take().unwrap().1)
				},
		}
	}

	fn next_hdshk_pub(&mut self) -> (HandshakeID, EncodedPoint) {
		match &mut self.mode_dep {
			ModeDependant::Server {
				..
			} => unreachable!(),
			ModeDependant::Client {
				hdshk_priv,
				..
			} => {
				let private = EphemeralSecret::random(&mut OsRng);
				let public = EncodedPoint::from(private.public_key());
				let mut handshake_id = [0_u8; 16];
				OsRng::fill(&mut OsRng, &mut handshake_id);
				*hdshk_priv = Some((handshake_id.clone(), private));
				(handshake_id, public)
			},
		}
	}
}

struct Crypto {
	negotiated: Instant,
	cipher: ChaCha20Poly1305,
	seq_send: u64,
	seq_recv: u64,
	nonce_send: ChaCha20Rng,
	nonce_recv: ChaCha20Rng,
	nonce_prev: HashMap<u64, Nonce>,
}

impl Crypto {
	fn new(pk_a: VerifyingKey, pk_b: VerifyingKey, secret: Hash, hdshk_id: &HandshakeID) -> Self {
		let snd_seed = {
			let mut hasher = blake3::Hasher::new();
			hasher.update(pk_a.to_bytes().as_slice());
			hasher.update(pk_b.to_bytes().as_slice());
			hasher.update(secret.as_bytes().as_slice());
			hasher.update(hdshk_id);
			hasher.finalize()
		};

		let rcv_seed = {
			let mut hasher = blake3::Hasher::new();
			hasher.update(pk_b.to_bytes().as_slice());
			hasher.update(pk_a.to_bytes().as_slice());
			hasher.update(secret.as_bytes().as_slice());
			hasher.update(hdshk_id);
			hasher.finalize()
		};

		Self {
			negotiated: Instant::now(),
			cipher: ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(secret.as_bytes())),
			seq_send: 0,
			seq_recv: 0,
			nonce_send: ChaCha20Rng::from_seed(snd_seed.into()),
			nonce_recv: ChaCha20Rng::from_seed(rcv_seed.into()),
			nonce_prev: HashMap::new(),
		}
	}

	fn encrypt(&mut self, mut message: Vec<u8>, pad: bool, length: bool) -> Result<(u64, Vec<u8>), SSError> {
		if message.len() > MAX_ENCRYPTED_PAYLOAD {
			return Err(SSError::MaxSizeExceeded);
		}

		if length {
			let mut msg_with_len = Vec::with_capacity(message.len() + 2);
			msg_with_len.extend_from_slice(&(message.len() as u16).to_le_bytes());
			msg_with_len.append(&mut message);
			message = msg_with_len;
		}

		if pad && message.len() < 64 {
			let start = message.len();
			message.resize(64, 0);
			OsRng::fill(&mut OsRng, &mut message[start..]);
		}

		let mut nonce_bytes = [0_u8; 12];
		self.nonce_send.fill_bytes(&mut nonce_bytes);
		self.seq_send += 1;
		let out =
			self.cipher.encrypt(&Nonce::from(nonce_bytes), message.as_slice()).map_err(|_| SSError::Encrypt)?;
		Ok((self.seq_send - 1, out))
	}

	fn decrypt(&mut self, seq: u64, encrypted: &[u8], length: bool) -> Result<Vec<u8>, SSError> {
		let nonce = if seq < self.seq_recv {
			match self.nonce_prev.remove(&seq) {
				Some(nonce) => nonce,
				None => return Err(SSError::LateOrDuplicate),
			}
		} else if seq > self.seq_recv {
			let late_seq_start = if seq - self.seq_recv > PREV_NONCE_WINDOW as u64 {
				self.nonce_prev.clear();
				seq - PREV_NONCE_WINDOW as u64
			} else {
				self.seq_recv
			};

			for late_seq in self.seq_recv..seq {
				let mut nonce_bytes = [0_u8; 12];
				self.nonce_recv.fill_bytes(&mut nonce_bytes);

				if late_seq >= late_seq_start {
					self.nonce_prev.insert(late_seq, Nonce::from(nonce_bytes));
				}

				self.seq_recv += 1;
			}

			if self.nonce_prev.len() > PREV_NONCE_WINDOW {
				let remove_amt = self.nonce_prev.len() - PREV_NONCE_WINDOW;
				let mut keys: Vec<u64> = self.nonce_prev.keys().cloned().collect();
				keys.sort_unstable();

				for (_, key) in (0..remove_amt).into_iter().zip(keys.into_iter()) {
					self.nonce_prev.remove(&key);
				}
			}

			let mut nonce_bytes = [0_u8; 12];
			self.nonce_recv.fill_bytes(&mut nonce_bytes);
			self.seq_recv += 1;
			Nonce::from(nonce_bytes)
		} else {
			let mut nonce_bytes = [0_u8; 12];
			self.nonce_recv.fill_bytes(&mut nonce_bytes);
			self.seq_recv += 1;
			Nonce::from(nonce_bytes)
		};

		let mut decrypted = self.cipher.decrypt(&nonce, encrypted).map_err(|_| SSError::Decrypt)?;

		if length {
			if decrypted.len() < 2 {
				return Err(SSError::Truncated);
			}

			let length = u16::from_le_bytes(<[u8; 2]>::try_from(&decrypted[0..2]).unwrap()) as usize;

			if length > decrypted.len() {
				return Err(SSError::Truncated);
			}

			let mut out = decrypted.split_off(2);
			out.truncate(length);
			Ok(out)
		} else {
			Ok(decrypted)
		}
	}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SSError {
	Bind(io::ErrorKind),
	Send(io::ErrorKind),
	MaxSizeExceeded,
	Encrypt,
	LateOrDuplicate,
	Decrypt,
	Truncated,
	ClientOnlyMethod,
	ServerOnlyMethod,
	NotConnected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketType {
	HdshkReq,
	EncHdshkReq,
	HdshkRes,
	EncHdshkRes,
	Ping,
	Message,
}

impl fmt::Display for PacketType {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::HdshkReq => write!(f, "HdshkReq"),
			Self::EncHdshkReq => write!(f, "EncHdshkReq"),
			Self::HdshkRes => write!(f, "HdshkRes"),
			Self::EncHdshkRes => write!(f, "EncHdshkRes"),
			Self::Ping => write!(f, "Ping"),
			Self::Message => write!(f, "Message"),
		}
	}
}

impl PacketType {
	fn from_byte(byte: &u8) -> Option<Self> {
		Some(match byte {
			1 => Self::HdshkReq,
			2 => Self::EncHdshkReq,
			3 => Self::HdshkRes,
			4 => Self::EncHdshkRes,
			5 => Self::Ping,
			6 => Self::Message,
			_ => return None,
		})
	}

	fn as_byte(&self) -> u8 {
		match self {
			Self::HdshkReq => 1,
			Self::EncHdshkReq => 2,
			Self::HdshkRes => 3,
			Self::EncHdshkRes => 4,
			Self::Ping => 5,
			Self::Message => 6,
		}
	}
}

macro_rules! up_or_ret {
	( $e:expr ) => {
		match $e.upgrade() {
			Some(some) => some,
			None => return,
		}
	};
}

impl SecureSocket {
	pub fn listen(
		keys: HostKeys,
		addr: SocketAddr,
		on_receive: OnReceiveFn,
		on_connect: OnConnectFn,
		on_disconnect: OnDisconnectFn,
	) -> Result<Arc<Self>, SSError> {
		let udp_socket = Arc::new(UdpSocket::bind(addr).map_err(|e| SSError::Bind(e.kind()))?);
		udp_socket.set_write_timeout(Some(Duration::from_millis(350))).unwrap();
		udp_socket.set_read_timeout(Some(Duration::from_millis(350))).unwrap();

		let socket = Arc::new(Self {
			keys,
			mode: Mode::Server,
			peer: Mutex::new(HashMap::new()),
			udp_socket,
			recv_thrd_h: Mutex::new(None),
		});

		socket.spawn_recv_thrd(on_receive, on_connect, on_disconnect);
		Ok(socket)
	}

	pub fn connect(
		keys: HostKeys,
		addr: SocketAddr,
		on_receive: OnReceiveFn,
		on_connect: OnConnectFn,
		on_disconnect: OnDisconnectFn,
	) -> Result<Arc<Self>, SSError> {
		let udp_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").map_err(|e| SSError::Bind(e.kind()))?);
		udp_socket.set_write_timeout(Some(Duration::from_millis(350))).unwrap();
		udp_socket.set_read_timeout(Some(Duration::from_millis(350))).unwrap();

		let peer = Peer {
			addr,
			crypto: HashMap::new(),
			mode_dep: ModeDependant::Client {
				ping_sent: Instant::now(),
				ping_recv: Instant::now(),
				hdshk_sent: Instant::now(),
				hdshk_priv: None,
				peer_id: None,
			},
		};

		let mut peers = HashMap::new();
		peers.insert(ZERO_HOST_ID.into(), peer);

		let socket = Arc::new(Self {
			keys,
			mode: Mode::Client,
			peer: Mutex::new(peers),
			udp_socket,
			recv_thrd_h: Mutex::new(None),
		});

		socket.spawn_recv_thrd(on_receive, on_connect, on_disconnect);
		Ok(socket)
	}

	pub fn wait_for_exit(&self) -> Result<(), ()> {
		match self.recv_thrd_h.lock().take() {
			Some(thrd_h) =>
				match thrd_h.join() {
					Ok(_) => Ok(()),
					Err(_) => Err(()),
				},
			None => Err(()),
		}
	}

	fn spawn_recv_thrd(
		self: &Arc<Self>,
		mut on_receive: OnReceiveFn,
		mut on_connect: OnConnectFn,
		mut on_disconnect: OnDisconnectFn,
	) {
		let socket_wk = Arc::downgrade(self);
		let mode = self.mode;
		let udp_socket = self.udp_socket.clone();

		*self.recv_thrd_h.lock() = Some(thread::spawn(move || {
			let mut recv_buf = vec![0_u8; 65535];
			let mut last_checkup = Instant::now();

			loop {
				if last_checkup.elapsed() >= CHECK_UP_INTERVAL {
					match mode {
						Mode::Server => {
							let socket = up_or_ret!(socket_wk);
							let mut call_disconnect = Vec::new();

							socket.peer.lock().retain(|peer_id, peer| {
								if peer.last_ping_recv().elapsed() > PING_DISCONNECT {
									println!(
										"[SS-{}][Connection]: Connection lost to {}, reason: no ping received.",
										mode, peer.addr
									);
									call_disconnect.push(peer_id.clone());
									false
								} else {
									match peer.last_hdshk_recv() {
										Some(inst) =>
											if inst.elapsed() > HANDSHAKE_DISCONNECT {
												println!(
													"[SS-{}][Connection]: Connection lost to {}, reason: no \
													 renegotiation received.",
													mode, peer.addr
												);
												call_disconnect.push(peer_id.clone());
												false
											} else {
												true
											},
										None => {
											println!(
												"[SS-{}][Connection]: Connection lost to {}, reason: no active \
												 connection.",
												mode, peer.addr
											);
											call_disconnect.push(peer_id.clone());
											false
										},
									}
								}
							});

							for peer_id in call_disconnect {
								on_disconnect(&socket, peer_id);
							}
						},
						Mode::Client => {
							let socket = up_or_ret!(socket_wk);
							let mut peers = socket.peer.lock();
							debug_assert!(peers.len() == 1);
							let peer = peers.values_mut().next().unwrap();

							if peer.crypto.is_empty() {
								if !peer.hdshk_pending() || peer.last_hdshk_sent().elapsed() >= HANDSHAKE_TIMEOUT {
									let (hdshk_id, public) = peer.next_hdshk_pub();
									let mut message = Vec::with_capacity(64);
									message.extend_from_slice(&hdshk_id);
									debug_assert!(public.len() + 17 <= 255);
									message.push((public.len() + 17) as u8);
									message.extend_from_slice(public.as_bytes());
									let rng_start = message.len();
									debug_assert!(rng_start < 64);
									message.resize(64, 0);
									OsRng::fill(&mut OsRng, &mut message[rng_start..]);
									let mut signature_bytes = socket.keys.sign_message(&*message);
									let mut send_buf = Vec::with_capacity(98 + signature_bytes.len());
									send_buf.push(PacketType::HdshkReq.as_byte());
									send_buf.extend_from_slice(socket.keys.id().as_bytes());
									debug_assert!(signature_bytes.len() + 34 <= 255);
									send_buf.push((signature_bytes.len() + 34) as u8);
									send_buf.append(&mut signature_bytes);
									send_buf.append(&mut message);
									peer.set_hdshk_sent();
									println!("[SS-{}][Connection]: Connecting to {}.", mode, peer.addr);

									if let Err(e) = udp_socket.send_to(&*send_buf, peer.addr) {
										println!(
											"[SS-{}][Connection]: Failed to send handshake to {}, reason: {}",
											mode,
											peer.addr,
											e.kind()
										);
									}
								}
							} else {
								if peer.last_ping_recv().elapsed() > PING_DISCONNECT {
									println!(
										"[SS-{}][Connection]: Connection lost to {}, reason: no ping response.",
										mode, peer.addr
									);
									peer.crypto.clear();

									if let Some(peer_id) = peer.take_peer_id() {
										drop(peer);
										drop(peers);
										on_disconnect(&socket, peer_id);
									}

									continue;
								}

								if peer.last_ping_sent().elapsed() > PING_INTERVAL {
									let mut test = vec![0; 32];
									OsRng::fill(&mut OsRng, &mut *test);
									let mut send_msg = Vec::with_capacity(64);
									send_msg.extend_from_slice(hash(&*test).as_bytes());
									send_msg.append(&mut test);
									peer.set_ping_sent();
									let addr = peer.addr.clone();
									let (hdshk_id, crypto) = peer.latest_crypto().unwrap();

									if let Err(e) =
										socket.send_internal(addr, crypto, hdshk_id, PacketType::Ping, send_msg)
									{
										match e {
											SSError::Encrypt => {
												println!(
													"[SS-{}][Connection]: Connection lost to {}, reason: failed \
													 to send ping: encryption error.",
													mode, addr
												);
												peer.crypto.clear();
											},
											SSError::Send(kind) => {
												println!(
													"[SS-{}][Connection]: Connection lost to {}, reason: failed \
													 to send ping: {}",
													mode, addr, kind
												);
												peer.crypto.clear();
											},
											_ => unreachable!(),
										}

										if let Some(peer_id) = peer.take_peer_id() {
											drop(peer);
											drop(peers);
											on_disconnect(&socket, peer_id);
										}

										continue;
									}
								}

								if peer.last_hdshk_recv().unwrap().elapsed() > HANDSHAKE_INTERVAL {
									if peer.hdshk_pending() {
										if peer.last_hdshk_sent().elapsed() > HANDSHAKE_TIMEOUT {
											println!(
												"[SS-{}][Connection]: Connection lost to {}, reason: failed to \
												 renegotiate connection.",
												mode, peer.addr
											);
											peer.crypto.clear();

											if let Some(peer_id) = peer.take_peer_id() {
												drop(peer);
												drop(peers);
												on_disconnect(&socket, peer_id);
											}

											continue;
										}
									} else {
										let (hdshk_id, public) = peer.next_hdshk_pub();
										let mut signed_message = Vec::with_capacity(64);
										signed_message.extend_from_slice(&hdshk_id);
										debug_assert!(public.len() + 17 <= 255);
										signed_message.push((public.len() + 17) as u8);
										signed_message.extend_from_slice(public.as_bytes());
										let rng_start = signed_message.len();
										debug_assert!(rng_start < 64);
										signed_message.resize(64, 0);
										OsRng::fill(&mut OsRng, &mut signed_message[rng_start..]);
										let mut signature_bytes = socket.keys.sign_message(&*signed_message);
										let mut message = Vec::with_capacity(signature_bytes.len() + 65);
										debug_assert!(signature_bytes.len() + 1 <= 255);
										message.push((signature_bytes.len() + 1) as u8);
										message.append(&mut signature_bytes);
										message.append(&mut signed_message);
										peer.set_hdshk_sent();
										let addr = peer.addr.clone();
										let (old_hdshk_id, old_crypto) = peer.latest_crypto().unwrap();
										println!("[SS-{}][Connection]: Renegotiating with {}.", mode, addr);

										if let Err(e) = socket.send_internal(
											addr,
											old_crypto,
											old_hdshk_id,
											PacketType::EncHdshkReq,
											message,
										) {
											match e {
												SSError::Encrypt => {
													println!(
														"[SS-{}][Connection]: Connection lost to {}, reason: \
														 renegotiation failed: encryption error.",
														mode, addr
													);
													peer.crypto.clear();
												},
												SSError::Send(kind) => {
													println!(
														"[SS-{}][Connection]: Connection lost to {}, reason: \
														 renegotiation failed: {}",
														mode, addr, kind
													);
													peer.crypto.clear();
												},
												_ => unreachable!(),
											}

											if let Some(peer_id) = peer.take_peer_id() {
												drop(peer);
												drop(peers);
												on_disconnect(&socket, peer_id);
											}

											continue;
										}
									}
								}
							}
						},
					}

					last_checkup = Instant::now();
				}

				match udp_socket.recv_from(&mut *recv_buf) {
					Ok((len, addr)) => {
						if len == 0 {
							continue;
						}

						match PacketType::from_byte(&recv_buf[0]) {
							Some(PacketType::HdshkReq) => {
								if mode != Mode::Server {
									println!(
										"[SS-{}][HdshkReq]: Rejected packet from {}, reason: not operating as \
										 server.",
										mode, addr
									);
									continue;
								}

								if len < 34 {
									println!(
										"[SS-{}][HdshkReq]: Rejected packet from {}, reason: truncated (C1).",
										mode, addr
									);
									continue;
								}

								let peer_id = HostID::from(<[u8; 32]>::try_from(&recv_buf[1..33]).unwrap());
								let signature_end = recv_buf[33] as usize;

								if len < signature_end {
									println!(
										"[SS-{}][HdshkReq]: Rejected packet from {}, reason: truncated (C2).",
										mode, addr
									);
									continue;
								}

								let signature_bytes = &recv_buf[34..signature_end];

								if len < signature_end + 64 {
									println!(
										"[SS-{}][HdshkReq]: Rejected packet from {}, reason: truncated (C3).",
										mode, addr
									);
									continue;
								}

								let message_bytes = &recv_buf[signature_end..(signature_end + 64)];
								let socket = up_or_ret!(socket_wk);

								if let Err(e) = socket.keys.verify_message(peer_id, signature_bytes, message_bytes)
								{
									println!(
										"[SS-{}][HdshkReq]: Rejected packet from {}, reason: unable to verify: {}",
										mode, addr, e
									);
									continue;
								}

								let handshake_id: HandshakeID =
									<[u8; 16]>::try_from(&message_bytes[0..16]).unwrap();
								let public_end = message_bytes[16] as usize;

								if public_end > message_bytes.len() {
									println!(
										"[SS-{}][HdshkReq]: Rejected packet from {}, reason: truncated (C4).",
										mode, addr
									);
									continue;
								}

								let peer_public = match PublicKey::from_sec1_bytes(&message_bytes[17..public_end])
								{
									Ok(ok) => ok,
									Err(_) => {
										println!(
											"[SS-{}][HdshkReq]: Rejected packet from {}, reason: invalid public \
											 key.",
											mode, addr
										);
										continue;
									},
								};

								let private = EphemeralSecret::random(&mut OsRng);
								let public = EncodedPoint::from(private.public_key());
								let secret = hash(private.diffie_hellman(&peer_public).as_bytes().as_slice());

								let mut crypto = Crypto::new(
									socket.keys.public_key(),
									socket.keys.public_key_of(peer_id).unwrap(),
									secret,
									&handshake_id,
								);

								let mut signed_message = Vec::with_capacity(97);
								signed_message.extend_from_slice(&handshake_id);
								debug_assert!(public.as_bytes().len() + 17 <= 255);
								signed_message.push((public.as_bytes().len() + 17) as u8);
								signed_message.extend_from_slice(public.as_bytes());

								let mut test = vec![0_u8; 32];
								let mut message = Vec::with_capacity(64);
								message.extend_from_slice(hash(&*test).as_bytes());
								message.append(&mut test);

								let mut encrypted = match crypto.encrypt(message, false, false) {
									Ok((_, ok)) => ok,
									Err(_) => {
										println!(
											"[SS-{}][HdshkReq]: Failed to send response to {}, reason: \
											 encryption failed.",
											mode, addr
										);
										continue;
									},
								};

								signed_message.append(&mut encrypted);
								let mut signature_bytes = socket.keys.sign_message(&*signed_message);
								let mut send_buf =
									Vec::with_capacity(34 + signature_bytes.len() + signed_message.len());
								send_buf.push(PacketType::HdshkRes.as_byte());
								send_buf.extend_from_slice(socket.keys.id().as_bytes());
								debug_assert!(signature_bytes.len() + 34 <= 255);
								send_buf.push((signature_bytes.len() + 34) as u8);
								send_buf.append(&mut signature_bytes);
								send_buf.append(&mut signed_message);
								// Lock before send in case somehow we receive before state is set.
								let mut peers = socket.peer.lock();

								if let Err(e) = udp_socket.send_to(&*send_buf, &addr) {
									println!(
										"[SS-{}][HdshkReq]: Failed to send response to {}, reason: {}",
										mode,
										addr,
										e.kind()
									);
									continue;
								}

								let mut peer = Peer {
									addr,
									crypto: HashMap::new(),
									mode_dep: ModeDependant::Server {
										ping_recv: Instant::now(),
									},
								};

								peer.crypto.insert(handshake_id, crypto);
								peers.insert(peer_id, peer);
								drop(peers);
								println!("[SS-{}][Connection]: Accepted from {}.", mode, addr);
								on_connect(&socket, peer_id);
							},
							Some(PacketType::HdshkRes) => {
								if mode != Mode::Client {
									println!(
										"[SS-{}][HdshkRes]: Rejected packet from {}, reason: not operating as \
										 client.",
										mode, addr
									);
									continue;
								}

								if len < 34 {
									println!(
										"[SS-{}][HdshkRes]: Rejected packet from {}, reason: truncated (C1).",
										mode, addr
									);
									continue;
								}

								let peer_id = HostID::from(<[u8; 32]>::try_from(&recv_buf[1..33]).unwrap());
								let signature_end = recv_buf[33] as usize;

								if len < signature_end {
									println!(
										"[SS-{}][HdshkRes]: Rejected packet from {}, reason: truncated (C2).",
										mode, addr
									);
									continue;
								}

								let signature_bytes = &recv_buf[34..signature_end];

								if len < signature_end + 17 {
									println!(
										"[SS-{}][HdshkRes]: Rejected packet from {}, reason: truncated (C3).",
										mode, addr
									);
									continue;
								}

								let public_end = recv_buf[signature_end + 16] as usize;
								let message_end = public_end + signature_end + 80;

								if len < message_end {
									println!(
										"[SS-{}][HdshkRes]: Rejected packet from {}, reason: truncated (C4).",
										mode, addr
									);
									continue;
								}

								let message_bytes = &recv_buf[signature_end..len];
								let socket = up_or_ret!(socket_wk);

								if let Err(e) = socket.keys.verify_message(peer_id, signature_bytes, message_bytes)
								{
									println!(
										"[SS-{}][HdshkRes]: Rejected packet from {}, reason: unable to verify: {}",
										mode, addr, e
									);
									continue;
								}

								let handshake_id: HandshakeID =
									<[u8; 16]>::try_from(&message_bytes[0..16]).unwrap();
								let peer_public = match PublicKey::from_sec1_bytes(&message_bytes[17..public_end])
								{
									Ok(ok) => ok,
									Err(_) => {
										println!(
											"[SS-{}][HdshkRes]: Rejected packet from {}, reason: invalid public \
											 key.",
											mode, addr
										);
										continue;
									},
								};

								let mut peers = socket.peer.lock();
								let peer = match peers.get_mut(&ZERO_HOST_ID.into()) {
									Some(some) => some,
									None => {
										println!(
											"[SS-{}][HdshkRes]: Rejected packet from {}, reason: unknown \
											 handshake (C1).",
											mode, addr
										);
										continue;
									},
								};

								if addr != peer.addr {
									println!(
										"[SS-{}][HdshkRes]: Rejected packet from {}, reason: address mismatch.",
										mode, addr
									);
									continue;
								}

								let private = match peer.take_hdshk_priv(handshake_id) {
									Some(some) => some,
									None => {
										println!(
											"[SS-{}][HdshkRes]: Rejected packet from {}, reason: unknown \
											 handshake (C2).",
											mode, addr
										);
										continue;
									},
								};

								let secret = hash(private.diffie_hellman(&peer_public).as_bytes().as_slice());
								let mut crypto = Crypto::new(
									socket.keys.public_key(),
									socket.keys.public_key_of(peer_id).unwrap(),
									secret,
									&handshake_id,
								);

								let decrypted = match crypto.decrypt(
									0,
									&message_bytes[public_end..(public_end + 80)],
									false,
								) {
									Ok(ok) => ok,
									Err(_) => {
										println!(
											"[SS-{}][HdshkRes]: Rejected packet from {}, reason: test failed \
											 (C1).",
											mode, addr
										);
										continue;
									},
								};

								if decrypted.len() != 64 {
									println!(
										"[SS-{}][HdshkRes]: Rejected packet from {}, reason: test failed (C2).",
										mode, addr
									);
									continue;
								}

								if hash(&decrypted[32..]) != <[u8; 32]>::try_from(&decrypted[0..32]).unwrap() {
									println!(
										"[SS-{}][HdshkRes]: Rejected packet from {}, reason: test failed (C3).",
										mode, addr
									);
									continue;
								}

								peer.crypto.clear();
								peer.crypto.insert(handshake_id, crypto);
								peer.set_ping_sent();
								peer.set_ping_recv();
								peer.set_peer_id(Some(peer_id));
								drop(peer);
								drop(peers);
								println!("[SS-{}][Connection]: Accepted from {}.", mode, addr);
								on_connect(&socket, peer_id);
							},
							Some(packet_ty) => {
								match packet_ty {
									PacketType::EncHdshkRes =>
										if mode != Mode::Client {
											println!(
												"[SS-{}][{}]: Rejected packet from {}, reason: not operating as \
												 client.",
												mode, packet_ty, addr
											);
											continue;
										},
									PacketType::EncHdshkReq =>
										if mode != Mode::Server {
											println!(
												"[SS-{}][{}]: Rejected packet from {}, reason: not operating as \
												 server.",
												mode, packet_ty, addr
											);
											continue;
										},
									_ => (),
								}

								if len < 137 {
									println!(
										"[SS-{}][{}]: Rejected packet from {}, reason: truncated (C1).",
										mode, packet_ty, addr
									);
									continue;
								}

								let peer_id: HostID =
									HostID::from(<[u8; 32]>::try_from(&recv_buf[1..33]).unwrap());
								let socket = up_or_ret!(socket_wk);

								// Preliminary check to make sure the peer is known before doing anything.
								if !socket.keys.is_host_trusted(peer_id) {
									println!(
										"[SS-{}][{}]: Rejected packet from {}, reason: unknown peer.",
										mode, packet_ty, addr
									);
								}

								let hdshk_id: HandshakeID = <[u8; 16]>::try_from(&recv_buf[33..49]).unwrap();
								let seq = u64::from_le_bytes(<[u8; 8]>::try_from(&recv_buf[49..57]).unwrap());
								let mut peers = socket.peer.lock();

								let peer = match match mode {
									Mode::Client => peers.get_mut(&ZERO_HOST_ID.into()),
									Mode::Server => peers.get_mut(&peer_id),
								} {
									Some(some) => some,
									None => {
										println!(
											"[SS-{}][{}]: Rejected packet from {}, reason: no active connection.",
											mode, packet_ty, addr
										);
										continue;
									},
								};

								if peer.addr != addr {
									println!(
										"[SS-{}][{}]: Rejected packet from {}, reason: address mismatch.",
										mode, packet_ty, addr
									);
									continue;
								}

								if mode == Mode::Client && Some(peer_id) != peer.cur_peer_id() {
									println!(
										"[SS-{}][{}]: Rejected packet from {}, reason: host id mismatch.",
										mode, packet_ty, addr
									);
									continue;
								}

								let crypto = match peer.crypto.get_mut(&hdshk_id) {
									Some(some) => some,
									None => {
										println!(
											"[SS-{}][{}]: Rejected packet from {}, reason: old/invalid handshake.",
											mode, packet_ty, addr
										);
										continue;
									},
								};

								let message = match crypto.decrypt(
									seq,
									&recv_buf[57..len],
									packet_ty == PacketType::Message,
								) {
									Ok(ok) => ok,
									Err(e) => {
										println!(
											"[SS-{}][{}]: Rejected packet from {}, reason: decryption failed: \
											 {:?}",
											mode, packet_ty, addr, e
										);
										continue;
									},
								};

								match packet_ty {
									PacketType::EncHdshkReq => {
										let signature_end = message[0] as usize;

										if signature_end + 64 > message.len() {
											println!(
												"[SS-{}][{}]: Rejected packet from {}, reason: truncated (C2).",
												mode, packet_ty, addr
											);
											continue;
										}

										let signature_bytes = &message[1..signature_end];
										let signed_message = &message[signature_end..(signature_end + 64)];

										if let Err(e) =
											socket.keys.verify_message(peer_id, signature_bytes, signed_message)
										{
											println!(
												"[SS-{}][{}]: Rejected packet from {}, reason: unable to verify: \
												 {}",
												mode, packet_ty, addr, e
											);
											continue;
										}

										let new_hdshk_id: HandshakeID =
											<[u8; 16]>::try_from(&signed_message[0..16]).unwrap();
										let public_end = signed_message[16] as usize;

										if public_end > signed_message.len() {
											println!(
												"[SS-{}][{}]: Rejected packet from {}, reason: truncated (C3).",
												mode, packet_ty, addr
											);
											continue;
										}

										let peer_public =
											match PublicKey::from_sec1_bytes(&signed_message[17..public_end]) {
												Ok(ok) => ok,
												Err(_) => {
													println!(
														"[SS-{}][{}]: Rejected packet from {}, reason: invalid \
														 public key.",
														mode, packet_ty, addr
													);
													continue;
												},
											};

										let private = EphemeralSecret::random(&mut OsRng);
										let public = EncodedPoint::from(private.public_key());
										let secret =
											hash(private.diffie_hellman(&peer_public).as_bytes().as_slice());

										let mut new_crypto = Crypto::new(
											socket.keys.public_key(),
											socket.keys.public_key_of(peer_id).unwrap(),
											secret,
											&new_hdshk_id,
										);

										let mut test = vec![0_u8; 32];
										OsRng::fill(&mut OsRng, &mut *test);
										let mut res_test_msg = Vec::with_capacity(64);
										res_test_msg.extend_from_slice(hash(&*test).as_bytes());
										res_test_msg.append(&mut test);

										let mut res_enc_test_msg =
											match new_crypto.encrypt(res_test_msg, false, false) {
												Ok((_, ok)) => ok,
												Err(_) => {
													println!(
														"[SS-{}][{}]: Failed to send response to {}, reason: \
														 encryption failed.",
														mode, packet_ty, addr
													);
													continue;
												},
											};

										let mut res_signed_msg = Vec::with_capacity(public.as_bytes().len() + 82);
										res_signed_msg.extend_from_slice(&new_hdshk_id);
										debug_assert!(public.as_bytes().len() + 17 <= 255);
										res_signed_msg.push((public.as_bytes().len() + 17) as u8);
										res_signed_msg.extend_from_slice(public.as_bytes());
										res_signed_msg.append(&mut res_enc_test_msg);

										let mut signature_bytes = socket.keys.sign_message(&*res_signed_msg);
										let mut res_message =
											Vec::with_capacity(signature_bytes.len() + res_signed_msg.len() + 1);
										debug_assert!(signature_bytes.len() + 1 <= 255);
										res_message.push((signature_bytes.len() + 1) as u8);
										res_message.append(&mut signature_bytes);
										res_message.append(&mut res_signed_msg);

										if let Err(e) = socket.send_internal(
											addr,
											crypto,
											&hdshk_id,
											PacketType::EncHdshkRes,
											res_message,
										) {
											match e {
												SSError::Encrypt => {
													println!(
														"[SS-{}][{}]: Failed to send response to {}, reason: \
														 encryption failed.",
														mode, packet_ty, addr
													);
												},
												SSError::Send(kind) => {
													println!(
														"[SS-{}][{}]: Failed to send response to {}, reason: {}",
														mode, packet_ty, addr, kind
													);
												},
												_ => unreachable!(),
											}
										}

										drop(crypto);
										peer.crypto.retain(|id, _| *id == hdshk_id);
										peer.crypto.insert(new_hdshk_id, new_crypto);
										println!("[SS-{}][Connection]: Renegotiated with {}.", mode, addr);
									},
									PacketType::EncHdshkRes => {
										let signature_end = message[0] as usize;

										if signature_end + 17 > message.len() {
											println!(
												"[SS-{}][{}]: Rejected packet from {}, reason: truncated (C2).",
												mode, packet_ty, addr
											);
											continue;
										}

										if message.len()
											!= message[signature_end + 16] as usize + signature_end + 80
										{
											println!(
												"[SS-{}][{}]: Rejected packet from {}, reason: truncated (C3).",
												mode, packet_ty, addr
											);
											continue;
										}

										let signature_bytes = &message[1..signature_end];
										let signed_message = &message[signature_end..];

										if let Err(e) =
											socket.keys.verify_message(peer_id, signature_bytes, signed_message)
										{
											println!(
												"[SS-{}][{}]: Rejected packet from {}, reason: unable to verify: \
												 {}",
												mode, packet_ty, addr, e
											);
											continue;
										}

										let new_hdshk_id: HandshakeID =
											<[u8; 16]>::try_from(&signed_message[0..16]).unwrap();
										let public_end = signed_message[16] as usize;

										let peer_public =
											match PublicKey::from_sec1_bytes(&signed_message[17..public_end]) {
												Ok(ok) => ok,
												Err(_) => {
													println!(
														"[SS-{}][{}]: Rejected packet from {}, reason: invalid \
														 public key.",
														mode, packet_ty, addr
													);
													continue;
												},
											};

										let enc_test_msg = &signed_message[public_end..];
										debug_assert!(enc_test_msg.len() == 80);
										drop(crypto);

										let private = match peer.take_hdshk_priv(new_hdshk_id) {
											Some(some) => some,
											None => {
												println!(
													"[SS-{}][{}]: Rejected packet from {}, reason: unknown \
													 handshake (C2).",
													mode, packet_ty, addr
												);
												continue;
											},
										};

										let secret =
											hash(private.diffie_hellman(&peer_public).as_bytes().as_slice());
										let mut new_crypto = Crypto::new(
											socket.keys.public_key(),
											socket.keys.public_key_of(peer_id).unwrap(),
											secret,
											&new_hdshk_id,
										);

										let test_msg = match new_crypto.decrypt(0, enc_test_msg, false) {
											Ok(ok) => ok,
											Err(_) => {
												println!(
													"[SS-{}][{}]: Rejected packet from {}, reason: test failed \
													 (C1).",
													mode, packet_ty, addr
												);
												continue;
											},
										};

										if hash(&test_msg[32..]) != <[u8; 32]>::try_from(&test_msg[0..32]).unwrap()
										{
											println!(
												"[SS-{}][{}]: Rejected packet from {}, reason: test failed (C2).",
												mode, packet_ty, addr
											);
											continue;
										}

										peer.crypto.retain(|id, _| *id == hdshk_id);
										peer.crypto.insert(new_hdshk_id, new_crypto);
										peer.set_ping_sent();
										peer.set_ping_recv();
										println!("[SS-{}][Connection]: Renegotiated with {}.", mode, addr);
									},
									PacketType::Ping => {
										if hash(&message[32..64]) != <[u8; 32]>::try_from(&message[0..32]).unwrap()
										{
											println!(
												"[SS-{}][{}]: Rejected packet from {}, reason: hash mismatch.",
												mode, packet_ty, addr
											);
											continue;
										}

										match mode {
											Mode::Server => {
												let mut test = vec![0; 32];
												OsRng::fill(&mut OsRng, &mut *test);
												let mut send_msg = Vec::with_capacity(64);
												send_msg.extend_from_slice(hash(&*test).as_bytes());
												send_msg.append(&mut test);

												if let Err(e) = socket.send_internal(
													peer.addr,
													crypto,
													&hdshk_id,
													PacketType::Ping,
													send_msg,
												) {
													match e {
														SSError::Encrypt => {
															println!(
																"[SS-{}][{}]: Failed to send ping to {}, reason: \
																 encryption failed.",
																mode, packet_ty, peer.addr
															);
														},
														SSError::Send(kind) => {
															println!(
																"[SS-{}][{}]: Failed to send ping to {}, reason: \
																 {}",
																mode, packet_ty, peer.addr, kind
															);
														},
														_ => unreachable!(),
													}

													continue;
												}

												peer.set_ping_recv();
											},
											Mode::Client => {
												println!(
													"[SS-{}][Connection]: {} ms ping to {}.",
													mode,
													peer.last_ping_sent().elapsed().as_micros() as f32 / 1000.0,
													peer.addr
												);
												peer.set_ping_recv();
											},
										}
									},
									PacketType::Message => {
										drop(peer);
										drop(peers);
										on_receive(&socket, peer_id, message);
									},
									_ => unreachable!(),
								}
							},
							None =>
								println!(
									"[SS-{}]: Rejected packet from {}, reason: invalid packet type.",
									mode, addr
								),
						}
					},
					Err(e) =>
						match e.kind() {
							io::ErrorKind::TimedOut => (),
							io::ErrorKind::WouldBlock => (),
							io::ErrorKind::ConnectionReset => (),
							_ =>
								println!("[SS-{}][Connection]: Failed to receive from socket: {}", mode, e.kind()),
						},
				}
			}
		}));
	}

	pub fn send(&self, message: Vec<u8>) -> Result<(), SSError> {
		if self.mode != Mode::Client {
			return Err(SSError::ClientOnlyMethod);
		}

		let mut peers = self.peer.lock();
		debug_assert!(peers.len() == 1);
		let peer = peers.values_mut().next().unwrap();
		let addr = peer.addr.clone();
		let (hdshk_id, crypto) = peer.latest_crypto().ok_or(SSError::NotConnected)?;
		self.send_internal(addr, crypto, hdshk_id, PacketType::Message, message)
	}

	pub fn send_to(&self, message: Vec<u8>, peer_id: HostID) -> Result<(), SSError> {
		if self.mode != Mode::Server {
			return Err(SSError::ServerOnlyMethod);
		}

		let mut peers = self.peer.lock();
		let peer = peers.get_mut(&peer_id).ok_or(SSError::NotConnected)?;
		let addr = peer.addr.clone();
		let (hdshk_id, crypto) = peer.latest_crypto().ok_or(SSError::NotConnected)?;
		self.send_internal(addr, crypto, hdshk_id, PacketType::Message, message)
	}

	fn send_internal(
		&self,
		addr: SocketAddr,
		crypto: &mut Crypto,
		hdshk_id: &HandshakeID,
		ty: PacketType,
		message: Vec<u8>,
	) -> Result<(), SSError> {
		let is_message = ty == PacketType::Message;
		let (seq, mut encrypted) = crypto.encrypt(message, is_message, is_message)?;
		let mut send_buf = Vec::with_capacity(57 + encrypted.len());
		send_buf.push(ty.as_byte());
		send_buf.extend_from_slice(self.keys.id().as_bytes());
		send_buf.extend_from_slice(hdshk_id);
		send_buf.extend_from_slice(&seq.to_le_bytes());
		send_buf.append(&mut encrypted);
		self.udp_socket.send_to(&*send_buf, addr).map_err(|e| SSError::Send(e.kind())).map(|_| ())
	}
}

#[test]
fn secure_socket() {
	use std::thread;

	let mut s_host_keys = HostKeys::generate();
	let mut c_host_keys = HostKeys::generate();
	s_host_keys.trust(c_host_keys.enc_public_key()).unwrap();
	c_host_keys.trust(s_host_keys.enc_public_key()).unwrap();

	let s_thrd_h = thread::spawn(move || {
		let server = SecureSocket::listen(
			s_host_keys,
			([127, 0, 0, 1], 1026).into(),
			Box::new(move |_socket, _peer_id, _data| {}),
			Box::new(move |_socket, _peer_id| {}),
			Box::new(move |_socket, _peer_id| {}),
		)
		.unwrap();

		server.wait_for_exit().unwrap();
	});

	let c_thrd_h = thread::spawn(move || {
		let client = SecureSocket::connect(
			c_host_keys,
			([127, 0, 0, 1], 1026).into(),
			Box::new(move |_socket, _peer_id, _data| {}),
			Box::new(move |_socket, _peer_id| {}),
			Box::new(move |_socket, _peer_id| {}),
		)
		.unwrap();

		client.wait_for_exit().unwrap();
	});

	s_thrd_h.join().unwrap();
	c_thrd_h.join().unwrap();
}
