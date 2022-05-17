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

pub type SSSRecvFn = Box<dyn FnMut(&Arc<SecureSocketServer>, Hash, Vec<u8>) + Send>;
pub type SSSOnConnect = Box<dyn FnMut(&Arc<SecureSocketServer>, Hash) + Send>;
pub type SSSOnDisconnect = Box<dyn FnMut(&Arc<SecureSocketServer>, Hash) + Send>;
pub type SSCRecvFn = Box<dyn FnMut(&Arc<SecureSocketClient>, Vec<u8>) + Send>;
pub type SSCOnConnect = Box<dyn FnMut(&Arc<SecureSocketClient>) + Send>;
pub type SSCOnDisconnect = Box<dyn FnMut(&Arc<SecureSocketClient>) + Send>;

// Interval at which the client sends pings.
const PING_INTERVAL: Duration = Duration::from_secs(3);
// Max duration from previous ping before server disconnects client.
const PING_DISCONNECT: Duration = Duration::from_secs(5);
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

pub fn hash_slices(inputs: &[&[u8]]) -> Hash {
	let mut hasher = blake3::Hasher::new();

	for input in inputs {
		hasher.update(input);
	}

	hasher.finalize()
}

pub struct SecureSocketServer {
	host_keys: HostKeys,
	socket: UdpSocket,
	clients: Mutex<HashMap<Hash, ClientState>>,
	thrd_recv_h: Mutex<Option<JoinHandle<()>>>,
}

struct ClientState {
	addr: SocketAddr,
	verified: bool,
	ping_recv: Instant,
	last_handshake: Instant,
	crypto: CryptoState,
}

impl SecureSocketServer {
	pub fn listen<A: ToSocketAddrs>(
		host_keys: HostKeys,
		listen_addr: A,
		mut recv_fn: SSSRecvFn,
		mut on_connect: SSSOnConnect,
		mut on_disconnect: SSSOnDisconnect,
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
			let mut last_clients_check = Instant::now();

			loop {
				if last_clients_check.elapsed() > CLIENTS_CHECK_INTERVAL {
					let mut call_disconnect = Vec::new();

					host.clients.lock().retain(|client_id, client_state| {
						if client_state.verified {
							if client_state.ping_recv.elapsed() > PING_DISCONNECT {
								println!(
									"[Socket-H]: Connection lost to {:?}: no ping received in timeframe.",
									client_state.addr
								);

								call_disconnect.push(client_id.clone());
								false
							} else if client_state.last_handshake.elapsed() > HANDSHAKE_DISCONNECT {
								println!(
									"[Socket-H]: Connection lost to {:?}: expected renegotiation.",
									client_state.addr
								);

								call_disconnect.push(client_id.clone());
								false
							} else {
								true
							}
						} else {
							if client_state.ping_recv.elapsed() > HANDSHAKE_TIMEOUT {
								println!(
									"[Socket-H]: Connection lost to {:?}: handshake timed out",
									client_state.addr
								);

								call_disconnect.push(client_id.clone());
								false
							} else {
								true
							}
						}
					});

					for client_id in call_disconnect {
						on_disconnect(&host, client_id);
					}

					last_clients_check = Instant::now();
				}

				match host.socket.recv_from(&mut *socket_buf) {
					Ok((len, addr)) => {
						if len < 1 {
							continue;
						}

						match PacketType::from_repr(socket_buf[0]) {
							Some(packet_type) => {
								if packet_type == PacketType::ECDH {
									let ecdh_rcv = match ECDHRcv::new(&host.host_keys, &socket_buf[0..len]) {
										Ok(ok) => ok,
										Err(e) => {
											println!(
												"[Socket-H]: Rejected connection from {:?}, reason: {}",
												addr, e
											);
											continue;
										},
									};

									let ecdh_snd = ECDHSnd::new(&host.host_keys);

									if let Err(e) = host.socket.send_to(ecdh_snd.packet.as_slice(), addr.clone()) {
										println!(
											"[Socket-H]: Rejected connection from {:?}: reason: send error: {}",
											addr,
											e.kind()
										);
										continue;
									}

									let client_id = ecdh_rcv.hid.clone();
									let crypto = ecdh_snd.handshake(&host.host_keys, ecdh_rcv);

									host.clients.lock().insert(client_id, ClientState {
										addr,
										verified: false,
										ping_recv: Instant::now(),
										last_handshake: Instant::now(),
										crypto,
									});

									println!("[Socket-H]: Connection pending with {:?}", addr);
									continue;
								}

								if len < 123 {
									println!("[Socket-H]: Rejected packet from {:?}, reason: truncated", addr);
									continue;
								}

								let c_id_b: [u8; 32] = socket_buf[1..33].try_into().unwrap();
								let c_id = Hash::from(c_id_b);
								let seq_b: [u8; 8] = socket_buf[33..41].try_into().unwrap();
								let seq = u64::from_le_bytes(seq_b);
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

								let msg = match client_state.crypto.decrypt(seq, &socket_buf[41..len]) {
									Ok(ok) => ok,
									Err(e @ CryptoError::Decryption) | Err(e @ CryptoError::Truncated) => {
										println!("[Socket-H]: Connection drop to {:?}: {}", addr, e);
										drop(client_state);
										clients.remove(&c_id);
										drop(clients);
										on_disconnect(&host, c_id);
										continue;
									},
									Err(e) => {
										println!("[Socket-H]: Rejected packet from {:?}, reason: {}", addr, e);
										continue;
									},
								};

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

										client_state.verified = true;
										client_state.ping_recv = Instant::now();
										client_state.last_handshake = Instant::now();

										drop(client_state);
										drop(clients);
										on_connect(&host, c_id);
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
							std::io::ErrorKind::TimedOut => (),
							kind => println!("[Socket-H]: Failed to receive packet: {}", kind),
						},
				}
			}
		}));

		Ok(host_ret)
	}

	pub fn send(&self, client_id: Hash, data: Vec<u8>) -> Result<(), SendError> {
		let mut clients = self.clients.lock();
		let mut client_state = clients.get_mut(&client_id).ok_or(SendError::NotConnected)?;
		self.send_internal(&mut client_state, PacketType::Message, data)
	}

	fn send_internal(
		&self,
		client_state: &mut ClientState,
		packet_type: PacketType,
		data: Vec<u8>,
	) -> Result<(), SendError> {
		if packet_type != PacketType::Verify && !client_state.verified {
			return Err(SendError::NotVerified);
		}

		let mut send_buf = Vec::with_capacity(129);
		send_buf.push(packet_type as u8);
		send_buf.extend_from_slice(self.host_keys.id().as_bytes());
		let (seq, mut encrypted) = client_state.crypto.encrypt(data)?;
		send_buf.extend_from_slice(&seq.to_le_bytes());
		send_buf.append(&mut encrypted);
		self.socket.send_to(&*send_buf, client_state.addr.clone())?;
		Ok(())
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
	renegotiating: bool,
	crypto: CryptoState,
}

impl SecureSocketClient {
	pub fn connect<A: ToSocketAddrs>(
		host_keys: HostKeys,
		host_addr: A,
		mut recv_fn: SSCRecvFn,
		mut on_connect: SSCOnConnect,
		mut on_disconnect: SSCOnDisconnect,
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
			let mut socket_buf = vec![0_u8; 65535];
			let mut client_state_set = false;
			let mut client_state_verified = false;
			let mut ecdh_data_op: Option<ECDHSnd> = None;
			let mut ping_recv = Instant::now();
			let mut ping_sent = Instant::now();
			let mut ping_pending = false;
			let mut handshake_last = Instant::now();
			let mut renegotiating = false;

			loop {
				if !client_state_set {
					if ecdh_data_op.is_none() {
						ecdh_data_op = Some(ECDHSnd::new(&client.host_keys));
					}

					if let Err(e) = client.socket.send(ecdh_data_op.as_ref().unwrap().packet.as_slice()) {
						println!("[Socket-C]: Failed to send ECDH packet: {}", e.kind());
						continue;
					}
				} else if client_state_verified {
					if handshake_last.elapsed() > HANDSHAKE_INTERVAL {
						if ecdh_data_op.is_none() {
							ecdh_data_op = Some(ECDHSnd::new(&client.host_keys));
							client.state.lock().as_mut().unwrap().renegotiating = true;
							renegotiating = true;
							println!("[Socket-C]: Renegotiating connection to host.");
						}

						if let Err(e) = client.socket.send(ecdh_data_op.as_ref().unwrap().packet.as_slice()) {
							*client.state.lock() = None;
							client_state_set = false;
							client_state_verified = false;
							on_disconnect(&client);
							println!("[Socket-C]: Connection lost: failed to send ECDH packet: {}", e.kind());
							continue;
						}
					}

					if !renegotiating && ping_recv.elapsed() > PING_INTERVAL {
						if ping_recv.elapsed() > PING_DISCONNECT {
							*client.state.lock() = None;
							client_state_set = false;
							client_state_verified = false;
							on_disconnect(&client);
							println!("[Socket-C]: Connection lost: failed to receive ping response from host.");
						}

						if !ping_pending {
							ping_sent = Instant::now();
							ping_pending = true;

							if let Err(e) = client.send_internal(PacketType::Ping, Vec::new()) {
								*client.state.lock() = None;
								client_state_set = false;
								client_state_verified = false;
								on_disconnect(&client);
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
										if client_state_set && !renegotiating {
											println!(
												"[Socket-C]: Received ECDH packet, but connection is already \
												 established."
											);
											continue;
										}

										let ecdh_rcv = match ECDHRcv::new(&client.host_keys, &socket_buf[0..len]) {
											Ok(ok) => ok,
											Err(e) => {
												println!("[Socket-C]: Received ECDH packet, but {}", e);
												continue;
											},
										};

										let crypto =
											ecdh_data_op.take().unwrap().handshake(&client.host_keys, ecdh_rcv);

										*client.state.lock() = Some(SSCState {
											verified: false,
											renegotiating: false,
											crypto,
										});

										client_state_set = true;
										client_state_verified = false;
										renegotiating = false;

										println!("[Socket-C]: Connection is now pending verification.");

										let mut rand_data = [0_u8; 32];
										OsRng::fill(&mut OsRng, &mut rand_data);
										let rand_hash = hash(&rand_data);
										let mut r_msg = Vec::with_capacity(64);
										r_msg.extend_from_slice(&rand_data);
										r_msg.extend_from_slice(rand_hash.as_bytes());

										if let Err(e) = client.send_internal(PacketType::Verify, r_msg) {
											*client.state.lock() = None;
											client_state_set = false;

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

										if len < 123 {
											println!("[Socket-C]: Received message, but it is truncated.");
											continue;
										}

										let h_id_b: [u8; 32] = socket_buf[1..33].try_into().unwrap();
										let h_id = Hash::from(h_id_b);

										if !client.host_keys.is_host_trusted(h_id) {
											*client.state.lock() = None;
											client_state_set = false;
											client_state_verified = false;
											on_disconnect(&client);

											println!(
												"[Socket-C]: Connection dropped. Received message, but host \
												 isn't trusted."
											);
											continue;
										}

										let seq_b: [u8; 8] = socket_buf[33..41].try_into().unwrap();
										let seq = u64::from_le_bytes(seq_b);
										let mut client_state_gu = client.state.lock();
										let mut client_state = client_state_gu.as_mut().unwrap();

										let msg = match client_state.crypto.decrypt(seq, &socket_buf[41..len]) {
											Ok(ok) => ok,
											Err(e @ CryptoError::Decryption) | Err(e @ CryptoError::Truncated) => {
												drop(client_state);
												*client_state_gu = None;
												client_state_set = false;
												client_state_verified = false;
												on_disconnect(&client);
												println!("[Socket-C]: Connection dropped because {}", e);
												continue;
											},
											Err(e) => {
												println!("[Socket-C]: Packet dropped because {}", e);
												continue;
											},
										};

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
														"[Socket-C]: Connection verification failed, packet \
														 isn't the correct length"
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
												handshake_last = Instant::now();
												client.conn_cond.notify_all();
												drop(client_state);
												on_connect(&client);
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
											PacketType::Message => recv_fn(&client, msg),
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

	pub fn wait_for_conn(&self, timeout: Option<Duration>) {
		let mut client_state_gu = self.state.lock();

		while client_state_gu.is_none() || !client_state_gu.as_ref().unwrap().verified {
			match timeout.as_ref() {
				Some(duration) => {
					self.conn_cond.wait_for(&mut client_state_gu, duration.clone());
				},
				None => self.conn_cond.wait(&mut client_state_gu),
			}
		}
	}

	pub fn send(&self, data: Vec<u8>) -> Result<(), SendError> {
		self.send_internal(PacketType::Message, data)
	}

	fn send_internal(&self, packet_type: PacketType, data: Vec<u8>) -> Result<(), SendError> {
		let mut client_state_gu = self.state.lock();

		if client_state_gu.is_none() {
			return Err(SendError::NotConnected);
		}

		let client_state = client_state_gu.as_mut().unwrap();

		if packet_type != PacketType::Verify && !client_state.verified {
			return Err(SendError::NotVerified);
		}

		if client_state.renegotiating {
			drop(client_state_gu);
			self.wait_for_conn(Some(HANDSHAKE_TIMEOUT.clone()));
			return self.send_internal(packet_type, data);
		}

		let mut send_buf = Vec::with_capacity(129);
		send_buf.push(packet_type as u8);
		send_buf.extend_from_slice(self.host_keys.id().as_bytes());
		let (seq, mut encrypted) = client_state.crypto.encrypt(data)?;
		send_buf.extend_from_slice(&seq.to_le_bytes());
		send_buf.append(&mut encrypted);
		self.socket.send(&*send_buf)?;
		Ok(())
	}

	pub fn wait_for_exit(&self) -> Result<(), String> {
		if let Some(thrd_recv_h) = self.thrd_recv_h.lock().take() {
			thrd_recv_h.join().map_err(|_| format!("panicked"))?;
		}

		Ok(())
	}
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
	hid: Hash,
	public: PublicKey,
	random: Vec<u8>,
}

impl ECDHRcv {
	fn new(host_keys: &HostKeys, buffer: &[u8]) -> Result<Self, String> {
		if buffer.len() < 34 {
			return Err(String::from("host-id truncated"));
		}

		let hid_b: [u8; 32] = buffer[1..33].try_into().unwrap();
		let hid = Hash::from(hid_b);
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
