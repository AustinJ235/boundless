use crate::host_keys::HostKeys;
use blake3::{hash, Hash};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use k256::ecdh::EphemeralSecret;
use k256::{EncodedPoint, PublicKey};
use parking_lot::{Condvar, Mutex};
use rand::rngs::OsRng;
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use strum::FromRepr;

pub type HostRecvFn = Box<dyn Fn(&Arc<SecureSocketHost>, Hash, Vec<u8>) + Send>;
pub type ClientRecvFn = Box<dyn Fn(&Arc<SecureSocketClient>, Vec<u8>) + Send>;

const PING_INTERVAL: Duration = Duration::from_millis(3000);
const PING_DISCONNECT: Duration = Duration::from_millis(4000);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(1000);

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

pub fn hash_slices(inputs: &[&[u8]]) -> Hash {
	let mut hasher = blake3::Hasher::new();

	for input in inputs {
		hasher.update(input);
	}

	hasher.finalize()
}

pub struct SecureSocketHost {
	host_keys: HostKeys,
	socket: UdpSocket,
	clients: Mutex<HashMap<Hash, ClientState>>,
	thrd_recv_h: Mutex<Option<JoinHandle<()>>>,
}

struct ClientState {
	addr: SocketAddr,
	cipher: ChaCha20Poly1305,
	hs_status: HandshakeStatus,
	snd_seq: u64,
	rcv_seq: u64,
	nonce_rng_snd: ChaCha20Rng,
	nonce_rng_rcv: ChaCha20Rng,
	ping_recv: Instant,
}

#[derive(PartialEq, Eq)]
enum HandshakeStatus {
	Pending,
	Complete,
}

impl SecureSocketHost {
	pub fn listen<A: ToSocketAddrs>(
		host_keys: HostKeys,
		listen_addr: A,
		recv_fn: HostRecvFn,
	) -> Result<Arc<Self>, String> {
		let listen_addr = listen_addr.to_socket_addrs().unwrap().next().unwrap();
		let socket = UdpSocket::bind(listen_addr.clone()).map_err(|e| format!("Failed to bind socket: {}", e))?;
		socket.set_read_timeout(Some(Duration::from_millis(350))).unwrap();

		println!("[Socket-H]: Listening on {:?}", listen_addr);

		let host_ret = Arc::new(Self {
			host_keys,
			socket,
			clients: Mutex::new(HashMap::new()),
			thrd_recv_h: Mutex::new(None),
		});

		let host = host_ret.clone();

		*host_ret.thrd_recv_h.lock() = Some(thread::spawn(move || {
			let mut socket_buf = vec![0_u8; 65535];

			loop {
				match host.socket.recv_from(&mut *socket_buf) {
					Ok((len, addr)) => {
						if len < 1 {
							continue;
						}

						match PacketType::from_repr(socket_buf[0]) {
							Some(packet_type) => {
								if packet_type == PacketType::ECDH {
									if len < 35 {
										println!(
											"[Socket-H]: Rejected connection from {:?}, reason: packet truncated",
											addr
										);
										continue;
									}

									let c_id_b: [u8; 32] = (&socket_buf[1..33]).try_into().unwrap();
									let c_id = Hash::from(c_id_b);
									let sig_len = socket_buf[33] as usize;
									let sig_end = 34 + sig_len;

									if sig_end > len {
										println!(
											"[Socket-H]: Rejected connection from {:?}, reason: signature \
											 truncated",
											addr
										);
										continue;
									}

									let sig_b = &socket_buf[34..sig_end];
									let msg_end = sig_end as usize + 64;

									if msg_end > len {
										println!(
											"[Socket-H]: Rejected connection from {:?}, reason: message truncated",
											addr
										);
										continue;
									}

									let msg = &socket_buf[sig_end..msg_end];

									if let Err(e) = host.host_keys.verify_message(c_id, sig_b, msg) {
										println!("[Socket-H]: Rejected connection from {:?}, reason: {}", addr, e);
										continue;
									}

									let c_dh_pub_len = msg[0] as usize;

									if c_dh_pub_len > 63 {
										println!(
											"[Socket-H]: Rejected connection from {:?}, reason: publick key \
											 truncated",
											addr
										);
										continue;
									}

									let c_dh_pub = match PublicKey::from_sec1_bytes(&msg[1..(1 + c_dh_pub_len)]) {
										Ok(ok) => ok,
										Err(_) => {
											println!(
												"[Socket-H]: Rejected connection from {:?}, reason: invalid \
												 public key",
												addr
											);
											continue;
										},
									};

									let c_random = &msg[(1 + c_dh_pub_len)..64];
									let dh_secret = EphemeralSecret::random(&mut OsRng);
									let dh_public = EncodedPoint::from(dh_secret.public_key());
									let secret = hash(dh_secret.diffie_hellman(&c_dh_pub).as_bytes().as_slice());

									let mut ecdh_data = Vec::with_capacity(64);
									ecdh_data.push(0);
									ecdh_data.extend_from_slice(dh_public.as_bytes());
									ecdh_data[0] = (ecdh_data.len() - 1) as u8;

									let mut h_random = vec![0_u8; 64 - ecdh_data.len()];
									OsRng::fill(&mut OsRng, h_random.as_mut_slice());
									ecdh_data.extend_from_slice(&h_random);

									let mut ecdh_buf = Vec::with_capacity(170);
									ecdh_buf.push(PacketType::ECDH as u8);
									ecdh_buf.extend_from_slice(host.host_keys.id().as_bytes());
									ecdh_buf.push(0);
									ecdh_buf.append(&mut host.host_keys.sign_message(&ecdh_data));
									ecdh_buf[33] = (ecdh_buf.len() - 34) as u8;
									ecdh_buf.append(&mut ecdh_data);

									if let Err(e) = host.socket.send_to(&ecdh_buf, addr.clone()) {
										println!(
											"[Socket-H]: Rejected connection from {:?}: reason: send error: {}",
											addr,
											e.kind()
										);
										continue;
									}

									let nonce_rng_snd = ChaCha20Rng::from_seed(
										hash_slices(&[
											host.host_keys.id().as_bytes(),
											&h_random,
											c_id.as_bytes(),
											c_random,
											secret.as_bytes(),
										])
										.into(),
									);

									let nonce_rng_rcv = ChaCha20Rng::from_seed(
										hash_slices(&[
											c_id.as_bytes(),
											c_random,
											host.host_keys.id().as_bytes(),
											&h_random,
											secret.as_bytes(),
										])
										.into(),
									);

									host.clients.lock().insert(c_id, ClientState {
										addr,
										hs_status: HandshakeStatus::Pending,
										nonce_rng_snd,
										nonce_rng_rcv,
										snd_seq: 0,
										rcv_seq: 0,
										cipher: ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(
											secret.as_bytes(),
										)),
										ping_recv: Instant::now(),
									});

									println!("[Socket-H]: Connection pending with {:?}", addr);
									continue;
								}

								if len < 129 {
									println!("[Socket-H]: Rejected packet from {:?}, reason: truncated", addr);
									continue;
								}

								let c_id_b: [u8; 32] = socket_buf[1..33].try_into().unwrap();
								let c_id = Hash::from(c_id_b);
								let seq_b: [u8; 8] = socket_buf[33..41].try_into().unwrap();
								let seq = u64::from_le_bytes(seq_b);
								let encrypted = &socket_buf[41..len];
								let mut clients = host.clients.lock();

								let mut client_state = match clients.get_mut(&c_id) {
									Some(some) => some,
									None => {
										println!(
											"[Socket-H]: Rejected packet from {:?}, reason: not connected",
											addr
										);
										continue;
									},
								};

								if seq > client_state.rcv_seq {
									println!("[Socket-H]: Rejected packet from {:?}, reason: late", addr);
									continue;
								}

								let mut nonce_b = [0_u8; 12];
								let mut dropped = 0_usize;

								while seq < client_state.rcv_seq {
									client_state.nonce_rng_rcv.fill_bytes(&mut nonce_b);
									client_state.rcv_seq += 1;
									dropped += 1;
								}

								// TODO: window?
								if dropped > 0 {
									println!("[Socket-H]: Detected {} dropped packets from {:?}", dropped, addr);
								}

								client_state.nonce_rng_rcv.fill_bytes(&mut nonce_b);
								let nonce = Nonce::from_slice(&nonce_b);
								client_state.rcv_seq += 1;

								let decrypted = match client_state.cipher.decrypt(nonce, encrypted) {
									Ok(ok) => ok,
									Err(e) => {
										println!(
											"[Socket-H]: Rejected packet from {:?}, reason: encryption error: {}",
											addr, e
										);
										continue;
									},
								};

								assert!(decrypted.len() >= 72);
								let msg_len_b: [u8; 8] = decrypted[0..8].try_into().unwrap();
								let msg_len = u64::from_le_bytes(msg_len_b) as usize;

								if msg_len > decrypted.len() + 8 {
									println!(
										"[Socket-H]: Rejected packet from {:?}, reason: invalid message length",
										addr
									);
									continue;
								}

								let msg = decrypted[8..(8 + msg_len)].to_vec();

								match packet_type {
									PacketType::ECDH => unreachable!(),
									PacketType::Verify => {
										if msg.len() != 64 {
											println!(
												"[Socket-H]: Rejected connection from {:?}, reason: verify \
												 length mismatch",
												addr
											);
											drop(client_state);
											clients.remove(&c_id);
											continue;
										}

										let msg_h_b: [u8; 32] = msg[32..64].try_into().unwrap();
										let msg_h = Hash::from(msg_h_b);

										if msg_h != hash(&msg[0..32]) {
											println!(
												"[Socket-H]: Rejected connection from {:?}, reason: verify hash \
												 mismatch",
												addr
											);
											drop(client_state);
											clients.remove(&c_id);
											continue;
										}

										let mut rand_data = [0_u8; 32];
										OsRng::fill(&mut OsRng, &mut rand_data);
										let rand_hash = hash(&rand_data);
										let mut r_msg = Vec::with_capacity(64);
										r_msg.extend_from_slice(&rand_data);
										r_msg.extend_from_slice(rand_hash.as_bytes());

										if let Err(e) =
											host.send_internal(&mut client_state, PacketType::Verify, r_msg)
										{
											println!(
												"[Socket-H]: Rejected connection from {:?}, reason: verify send \
												 error: {}",
												addr, e
											);
											drop(client_state);
											clients.remove(&c_id);
											continue;
										}

										client_state.hs_status = HandshakeStatus::Complete;
										client_state.ping_recv = Instant::now();
										println!("[Socket-H]: Connection established with {:?}", addr);
									},
									PacketType::Ping => {
										if let Err(e) =
											host.send_internal(&mut client_state, PacketType::Ping, Vec::new())
										{
											println!("[Socket-H]: Failed to response ping to {:?}: {}", addr, e);
											continue;
										}

										client_state.ping_recv = Instant::now();
									},
									PacketType::Message => {
										drop(client_state);
										drop(clients);
										recv_fn(&host, c_id, msg);
									},
								}
							},
							None =>
								println!(
									"[Socket-H]: Rejected packet from {:?}, reason: invalid packet type",
									addr
								),
						}
					},
					Err(e) =>
						match e.kind() {
							std::io::ErrorKind::TimedOut => {
								host.clients.lock().retain(|_, client_state| {
									match client_state.hs_status {
										HandshakeStatus::Pending =>
											if client_state.ping_recv.elapsed() > HANDSHAKE_TIMEOUT {
												println!(
													"[Socket-H]: Connection lost to {:?}: handshake timed out",
													client_state.addr
												);
												false
											} else {
												true
											},
										HandshakeStatus::Complete =>
											if client_state.ping_recv.elapsed() > PING_DISCONNECT {
												println!(
													"[Socket-H]: Connection lost to {:?}: no ping received in \
													 timeframe.",
													client_state.addr
												);
												false
											} else {
												true
											},
									}
								});
							},
							kind => println!("[Socket-H]: Failed to receive packet: {}", kind),
						},
				}
			}
		}));

		Ok(host_ret)
	}

	pub fn send(&self, client_id: Hash, data: Vec<u8>) -> Result<(), String> {
		let mut clients = self.clients.lock();
		let mut client_state = clients.get_mut(&client_id).ok_or(String::from("Client not connected."))?;
		self.send_internal(&mut client_state, PacketType::Message, data)
	}

	fn send_internal(
		&self,
		client_state: &mut ClientState,
		packet_type: PacketType,
		mut data: Vec<u8>,
	) -> Result<(), String> {
		let mut send_buf = Vec::with_capacity(129);
		send_buf.push(packet_type as u8);
		send_buf.extend_from_slice(self.host_keys.id().as_bytes());
		send_buf.extend_from_slice(&client_state.snd_seq.to_le_bytes());

		let mut nonce_b = [0_u8; 12];
		client_state.nonce_rng_snd.fill_bytes(&mut nonce_b);
		client_state.snd_seq += 1;

		let nonce = Nonce::from_slice(&nonce_b);
		let msg_len = data.len();
		let mut data_ext = Vec::with_capacity(72);
		data_ext.extend_from_slice(&(msg_len as u64).to_le_bytes());
		data_ext.append(&mut data);

		if data_ext.len() < 72 {
			let mut padding = vec![0_u8; 72 - data_ext.len()];
			OsRng::fill(&mut OsRng, padding.as_mut_slice());
			data_ext.append(&mut padding);
		}

		let mut encrypted = client_state
			.cipher
			.encrypt(nonce, &*data_ext)
			.map_err(|e| format!("Failed to encrypt data: {}", e))?;
		send_buf.append(&mut encrypted);

		match self.socket.send_to(&*send_buf, client_state.addr.clone()) {
			Ok(_) => Ok(()),
			Err(e) => Err(format!("Failed to send packet to {:?}: {}", client_state.addr, e.kind())),
		}
	}

	pub fn wait_for_exit(&self) -> Result<(), String> {
		if let Some(thrd_recv_h) = self.thrd_recv_h.lock().take() {
			thrd_recv_h.join().map_err(|_| format!("panicked"))?;
		}

		Ok(())
	}
}

pub struct SecureSocketClient {
	host_keys: HostKeys,
	socket: UdpSocket,
	state: Mutex<Option<SSCState>>,
	thrd_recv_h: Mutex<Option<JoinHandle<()>>>,
	conn_cond: Condvar,
}

struct SSCState {
	verified: bool,
	snd_seq: u64,
	rcv_seq: u64,
	nonce_rng_snd: ChaCha20Rng,
	nonce_rng_rcv: ChaCha20Rng,
	cipher: ChaCha20Poly1305,
}

impl SecureSocketClient {
	pub fn connect<A: ToSocketAddrs>(
		host_keys: HostKeys,
		host_addr: A,
		recv_fn: ClientRecvFn,
	) -> Result<Arc<Self>, String> {
		let host_addr = host_addr.to_socket_addrs().unwrap().next().unwrap();
		let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to bind socket: {}", e))?;
		socket.connect(host_addr.clone()).unwrap();
		socket.set_read_timeout(Some(Duration::from_millis(350))).unwrap();

		let client_ret = Arc::new(Self {
			host_keys,
			socket,
			state: Mutex::new(None),
			thrd_recv_h: Mutex::new(None),
			conn_cond: Condvar::new(),
		});

		let client = client_ret.clone();

		*client_ret.thrd_recv_h.lock() = Some(thread::spawn(move || {
			struct ECDHData {
				secret: EphemeralSecret,
				packet: Vec<u8>,
				random: Vec<u8>,
			}

			let mut socket_buf = vec![0_u8; 65535];
			let mut client_state_set = false;
			let mut client_state_verified = false;
			let mut ecdh_data_op: Option<ECDHData> = None;
			let mut ping_recv = Instant::now();
			let mut ping_sent = Instant::now();
			let mut ping_pending = false;

			loop {
				if !client_state_set {
					if ecdh_data_op.is_none() {
						let dh_secret = EphemeralSecret::random(&mut OsRng);
						let dh_public = EncodedPoint::from(dh_secret.public_key());

						let mut ecdh_data = Vec::with_capacity(64);
						ecdh_data.push(0);
						ecdh_data.extend_from_slice(dh_public.as_bytes());
						ecdh_data[0] = (ecdh_data.len() - 1) as u8;

						let mut c_random = vec![0_u8; 64 - ecdh_data.len()];
						OsRng::fill(&mut OsRng, c_random.as_mut_slice());
						ecdh_data.extend_from_slice(&c_random);

						let mut ecdh_buf = Vec::with_capacity(170);
						ecdh_buf.push(PacketType::ECDH as u8);
						ecdh_buf.extend_from_slice(client.host_keys.id().as_bytes());
						ecdh_buf.push(0);
						ecdh_buf.append(&mut client.host_keys.sign_message(&ecdh_data));
						ecdh_buf[33] = (ecdh_buf.len() - 34) as u8;
						ecdh_buf.append(&mut ecdh_data);

						ecdh_data_op = Some(ECDHData {
							secret: dh_secret,
							packet: ecdh_buf,
							random: c_random,
						});
					}

					let ecdh_data = ecdh_data_op.as_ref().unwrap();

					if let Err(e) = client.socket.send(ecdh_data.packet.as_slice()) {
						println!("[Socket-C]: Failed to send ECDH packet: {}", e.kind());
						continue;
					}
				} else if client_state_verified {
					if ping_recv.elapsed() > PING_INTERVAL {
						if ping_recv.elapsed() > PING_DISCONNECT {
							*client.state.lock() = None;
							client_state_set = false;
							client_state_verified = false;
							println!("[Socket-C]: Connection lost: failed to receive ping response from host.");
						}

						if !ping_pending {
							ping_sent = Instant::now();
							ping_pending = true;

							if let Err(e) = client.send_internal(true, PacketType::Ping, Vec::new()) {
								*client.state.lock() = None;
								client_state_set = false;
								client_state_verified = false;
								println!("[Socket-C]: Connection lost: failed to send ping to host: {}", e);
							}
						}
					}
				}

				match client.socket.recv(socket_buf.as_mut_slice()) {
					Ok(len) => {
						if len < 1 {
							continue;
						}

						match PacketType::from_repr(socket_buf[0]) {
							Some(packet_type) =>
								match packet_type {
									PacketType::ECDH => {
										if client_state_set {
											println!(
												"[Socket-C]: Received ECDH packet, but connection is already \
												 established."
											);
											continue;
										}

										let ecdh_data = ecdh_data_op.as_ref().unwrap();

										if len < 34 {
											println!("[Socket-C]: Received ECDH packet, but packet is truncated.");
											continue;
										}

										let h_id_b: [u8; 32] = socket_buf[1..33].try_into().unwrap();
										let h_id = Hash::from(h_id_b);
										let sig_len = socket_buf[33] as usize;
										let sig_end = 34 + sig_len;

										if sig_end > len {
											println!(
												"[Socket-C]: Received ECDH packet, but signature is truncated."
											);
											continue;
										}

										let sig_b = &socket_buf[34..sig_end];
										let msg_end = sig_end + 64;

										if msg_end > len {
											println!(
												"[Socket-C]: Received ECDH packet, but message is truncated."
											);
											continue;
										}

										let msg = &socket_buf[sig_end..msg_end];

										if let Err(_) = client.host_keys.verify_message(h_id, sig_b, msg) {
											println!(
												"[Socket-C]: Received ECDH packet, but failed to verify \
												 authenticity."
											);
											continue;
										}

										let h_dh_pub_len = msg[0] as usize;

										if h_dh_pub_len > 63 {
											println!(
												"[Socket-C]: Received ECDH packet, but public key is truncated."
											);
											continue;
										}

										let h_dh_pub =
											match PublicKey::from_sec1_bytes(&msg[1..(1 + h_dh_pub_len)]) {
												Ok(ok) => ok,
												Err(_) => {
													println!(
														"[Socket-C]: Received ECDH packet, but public key is \
														 invalid."
													);
													continue;
												},
											};

										let h_random = &msg[(1 + h_dh_pub_len)..64];
										let secret =
											hash(ecdh_data.secret.diffie_hellman(&h_dh_pub).as_bytes().as_slice());

										let nonce_rng_rcv = ChaCha20Rng::from_seed(
											hash_slices(&[
												h_id.as_bytes(),
												h_random,
												client.host_keys.id().as_bytes(),
												ecdh_data.random.as_slice(),
												secret.as_bytes(),
											])
											.into(),
										);

										let nonce_rng_snd = ChaCha20Rng::from_seed(
											hash_slices(&[
												client.host_keys.id().as_bytes(),
												ecdh_data.random.as_slice(),
												h_id.as_bytes(),
												h_random,
												secret.as_bytes(),
											])
											.into(),
										);

										*client.state.lock() = Some(SSCState {
											verified: false,
											nonce_rng_rcv,
											nonce_rng_snd,
											snd_seq: 0,
											rcv_seq: 0,
											cipher: ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(
												secret.as_bytes(),
											)),
										});

										client_state_set = true;
										client_state_verified = false;
										drop(ecdh_data);
										ecdh_data_op = None;

										println!("[Socket-C]: Connection is now pending verification.");

										let mut rand_data = [0_u8; 32];
										OsRng::fill(&mut OsRng, &mut rand_data);
										let rand_hash = hash(&rand_data);
										let mut r_msg = Vec::with_capacity(64);
										r_msg.extend_from_slice(&rand_data);
										r_msg.extend_from_slice(rand_hash.as_bytes());

										if let Err(e) = client.send_internal(false, PacketType::Verify, r_msg) {
											*client.state.lock() = None;
											client_state_set = false;
											client_state_verified = false;

											println!(
												"[Socket-C]: Connection verification failed, failed to send: {}",
												e
											);
										}
									},
									packet_type => {
										if !client_state_set {
											println!(
												"[Socket-C]: Received {:?} packet, but there is no connection.",
												packet_type
											);
											continue;
										}

										if len < 129 {
											println!("[Socket-C]: Received message, but it is truncated.");
											continue;
										}

										let h_id_b: [u8; 32] = socket_buf[1..33].try_into().unwrap();
										let h_id = Hash::from(h_id_b);

										if !client.host_keys.is_host_trusted(h_id) {
											*client.state.lock() = None;
											client_state_set = false;
											client_state_verified = false;

											println!(
												"[Socket-C]: Connection dropped. Received message, but host \
												 isn't trusted."
											);
											continue;
										}

										let seq_b: [u8; 8] = socket_buf[33..41].try_into().unwrap();
										let seq = u64::from_le_bytes(seq_b);
										let encrypted = &socket_buf[41..len];
										let mut client_state_gu = client.state.lock();
										let mut client_state = client_state_gu.as_mut().unwrap();

										if seq > client_state.rcv_seq {
											println!("[Socket-C]: Dropped message because it was late.");
											continue;
										}

										let mut nonce_b = [0_u8; 12];
										let mut dropped = 0_usize;

										// TODO: Should out of order packets be allowed or
										// should a window algo exist?
										while seq < client_state.rcv_seq {
											client_state.nonce_rng_rcv.fill_bytes(&mut nonce_b);
											client_state.rcv_seq += 1;
											dropped += 1;
										}

										if dropped > 0 {
											println!(
												"[Socket-C]: Detected {} dropped packets from host.",
												dropped
											);
										}

										client_state.nonce_rng_rcv.fill_bytes(&mut nonce_b);
										client_state.rcv_seq += 1;
										let nonce = Nonce::from_slice(&nonce_b);

										if dropped != 0 {
											println!("[Socket-C]: Detected {} lost packets.", dropped);
										}

										let decrypted = match client_state.cipher.decrypt(nonce, encrypted) {
											Ok(ok) => ok,
											Err(_) => {
												// TODO: Should a connection be dropped if
												// it is just one packet?
												drop(client_state);
												*client_state_gu = None;
												client_state_set = false;
												client_state_verified = false;

												println!(
													"[Socket-C]: Connection dropped. Failed to decrypt message."
												);
												continue;
											},
										};

										if decrypted.len() < 72 {
											drop(client_state);
											*client_state_gu = None;
											client_state_set = false;
											client_state_verified = false;

											println!(
												"[Socket-C]: Connection dropped. Decrypted message is truncated."
											);
											continue;
										}

										let msg_len_b: [u8; 8] = decrypted[0..8].try_into().unwrap();
										let msg_len = u64::from_le_bytes(msg_len_b) as usize;

										if msg_len > decrypted.len() + 8 {
											drop(client_state);
											*client_state_gu = None;
											client_state_set = false;
											client_state_verified = false;

											println!(
												"[Socket-C]: Connection dropped. Decrypted message is malformed."
											);
											continue;
										}

										let msg = &decrypted[8..(8 + msg_len)];

										match packet_type {
											PacketType::ECDH => unreachable!(),
											PacketType::Verify => {
												if client_state.verified {
													println!(
														"[Socket-C]: Received Verify packet, but connection is \
														 already established."
													);
													continue;
												}

												if msg.len() != 64 {
													*client.state.lock() = None;
													client_state_set = false;
													client_state_verified = false;

													println!(
														"[Socket-C]: Connection verification failed, packet is \
														 truncated."
													);
													continue;
												}

												let msg_h_b: [u8; 32] = msg[32..64].try_into().unwrap();
												let msg_h = Hash::from(msg_h_b);

												if msg_h != hash(&msg[0..32]) {
													drop(client_state);
													*client_state_gu = None;
													client_state_set = false;
													client_state_verified = false;

													println!(
														"[Socket-C]: Connection verification failed, hash \
														 mismatch."
													);
													continue;
												}

												client_state.verified = true;
												client_state_verified = true;
												client.conn_cond.notify_all();
												println!("[Socket-C]: Connection is established to the host.");
											},
											PacketType::Ping => {
												ping_recv = Instant::now();
												ping_pending = false;
												println!(
													"[Socket-C]: Ping to host: {:.2} ms",
													ping_sent.elapsed().as_micros() as f32 / 1000.0
												);
											},
											PacketType::Message => recv_fn(&client, msg.to_vec()),
										}
									},
								},
							None => println!("[Socket-C]: Failed to receive packet, reason: invalid packet type"),
						}
					},
					Err(e) =>
						match e.kind() {
							std::io::ErrorKind::TimedOut =>
								if !client_state_set {
									thread::sleep(Duration::from_secs(1));
								},
							kind => println!("[Socket-C]: Failed to receive packet, reason: {}", kind),
						},
				}
			}
		}));

		Ok(client_ret)
	}

	pub fn wait_for_conn(&self) {
		let mut client_state_gu = self.state.lock();

		while client_state_gu.is_none() || !client_state_gu.as_ref().unwrap().verified {
			self.conn_cond.wait(&mut client_state_gu);
		}
	}

	pub fn send(&self, data: Vec<u8>) -> Result<(), String> {
		self.send_internal(true, PacketType::Message, data)
	}

	fn send_internal(&self, verified: bool, packet_type: PacketType, mut data: Vec<u8>) -> Result<(), String> {
		let mut client_state_gu = self.state.lock();

		if client_state_gu.is_none() {
			return Err(format!("Connection not established"));
		}

		let mut client_state = client_state_gu.as_mut().unwrap();

		if verified && !client_state.verified {
			return Err(format!("Connection not verified"));
		}

		let mut send_buf = Vec::with_capacity(129);
		send_buf.push(packet_type as u8);
		send_buf.extend_from_slice(self.host_keys.id().as_bytes());
		send_buf.extend_from_slice(&client_state.snd_seq.to_le_bytes());

		let mut nonce_b = [0_u8; 12];
		client_state.nonce_rng_snd.fill_bytes(&mut nonce_b);
		client_state.snd_seq += 1;

		let nonce = Nonce::from_slice(&nonce_b);
		let msg_len = data.len();
		let mut data_ext = Vec::with_capacity(72);
		data_ext.extend_from_slice(&(msg_len as u64).to_le_bytes());
		data_ext.append(&mut data);

		if data_ext.len() < 72 {
			let mut padding = vec![0_u8; 72 - data_ext.len()];
			OsRng::fill(&mut OsRng, padding.as_mut_slice());
			data_ext.append(&mut padding);
		}

		let mut encrypted = client_state
			.cipher
			.encrypt(nonce, &*data_ext)
			.map_err(|e| format!("failed to encrypt data: {}", e))?;
		send_buf.append(&mut encrypted);

		self.socket.send(&*send_buf).map_err(|e| format!("send error: {}", e.kind()))?;

		Ok(())
	}

	pub fn wait_for_exit(&self) -> Result<(), String> {
		if let Some(thrd_recv_h) = self.thrd_recv_h.lock().take() {
			thrd_recv_h.join().map_err(|_| format!("panicked"))?;
		}

		Ok(())
	}
}

#[test]
fn test() {
	use std::thread;

	let mut h_host_keys = HostKeys::generate();
	let mut c_host_keys = HostKeys::generate();
	h_host_keys.trust(c_host_keys.enc_public_key()).unwrap();
	c_host_keys.trust(h_host_keys.enc_public_key()).unwrap();

	let h_thrd_h = thread::spawn(move || {
		let host = SecureSocketHost::listen(
			h_host_keys,
			"0.0.0.0:1026",
			Box::new(move |_host, _client_uid, _packet_data| {}),
		)
		.unwrap();

		host.wait_for_exit().unwrap();
	});

	let c_thrd_h = thread::spawn(move || {
		let client =
			SecureSocketClient::connect(c_host_keys, "127.0.0.1:1026", Box::new(move |_client, _packet_data| {}))
				.unwrap();

		client.wait_for_conn();
		client.wait_for_exit().unwrap();
	});

	h_thrd_h.join().unwrap();
	c_thrd_h.join().unwrap();
}
