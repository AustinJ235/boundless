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

// How often the clients sends pings.
const PING_INTERVAL: Duration = Duration::from_millis(3000);
// Time between the last ping received and when to disconnect client due to the connection being idle. Must be
// higher than PING_INTERVAL.
const PING_DISCONNECT: Duration = Duration::from_millis(4000);
// Time between start of handshake and when to cancel handshake due to the client not responding.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(1000);
// How often to renegotiate secrets. Time between last handshake and when to disconnect the client due to
// it not renegotiating. Must be higher than HANDSHAKE_INTERVAL.
// TODO: Increase to something reasonable
const HANDSHAKE_INTERVAL: Duration = Duration::from_secs(30);
const HANDSHAKE_MAX_ALLOWED: Duration = Duration::from_secs(32);

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
	last_handshake: Instant,
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

									let RngAndCipher {
										nonce_rng_snd,
										nonce_rng_rcv,
										cipher,
										other_host_id,
									} = ecdh_snd.handshake(&host.host_keys, ecdh_rcv);

									host.clients.lock().insert(other_host_id, ClientState {
										addr,
										hs_status: HandshakeStatus::Pending,
										nonce_rng_snd,
										nonce_rng_rcv,
										snd_seq: 0,
										rcv_seq: 0,
										cipher,
										ping_recv: Instant::now(),
										last_handshake: Instant::now(),
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
										client_state.last_handshake = Instant::now();
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
								// TODO: **SECURITY RISK** Move this to somewhere that isn't dependant on socket
								// idle.
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
											} else if client_state.last_handshake.elapsed() > HANDSHAKE_MAX_ALLOWED
											{
												println!(
													"[Socket-H]: Connection lost to {:?}: expected renegotiation.",
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
	renegotiating: bool,
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
							println!("[Socket-C]: Connection lost: failed to send ECDH packet: {}", e.kind());
							continue;
						}
					}

					if !renegotiating && ping_recv.elapsed() > PING_INTERVAL {
						if ping_recv.elapsed() > PING_DISCONNECT {
							*client.state.lock() = None;
							client_state_set = false;
							client_state_verified = false;
							println!("[Socket-C]: Connection lost: failed to receive ping response from host.");
						}

						if !ping_pending {
							ping_sent = Instant::now();
							ping_pending = true;

							if let Err(e) = client.send_internal(PacketType::Ping, Vec::new()) {
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

										let RngAndCipher {
											nonce_rng_snd,
											nonce_rng_rcv,
											cipher,
											..
										} = ecdh_data_op.take().unwrap().handshake(&client.host_keys, ecdh_rcv);

										*client.state.lock() = Some(SSCState {
											verified: false,
											nonce_rng_rcv,
											nonce_rng_snd,
											snd_seq: 0,
											rcv_seq: 0,
											cipher,
											renegotiating: false,
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
												handshake_last = Instant::now();
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

	pub fn send(&self, data: Vec<u8>) -> Result<(), String> {
		self.send_internal(PacketType::Message, data)
	}

	fn send_internal(&self, packet_type: PacketType, mut data: Vec<u8>) -> Result<(), String> {
		let mut client_state_gu = self.state.lock();

		if client_state_gu.is_none() {
			return Err(format!("Connection not established"));
		}

		let mut client_state = client_state_gu.as_mut().unwrap();

		if packet_type != PacketType::Verify && !client_state.verified {
			return Err(format!("Connection not verified"));
		}

		if client_state.renegotiating {
			drop(client_state_gu);
			self.wait_for_conn(Some(HANDSHAKE_TIMEOUT.clone()));
			return self.send_internal(packet_type, data);
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

	fn handshake(self, host_keys: &HostKeys, rcv: ECDHRcv) -> RngAndCipher {
		let secret = hash(self.secret.diffie_hellman(&rcv.public).as_bytes().as_slice());

		RngAndCipher {
			other_host_id: rcv.hid,
			nonce_rng_snd: ChaCha20Rng::from_seed(
				hash_slices(&[
					host_keys.id().as_bytes(),
					self.random.as_slice(),
					rcv.hid.as_bytes(),
					rcv.random.as_slice(),
					secret.as_bytes(),
				])
				.into(),
			),
			nonce_rng_rcv: ChaCha20Rng::from_seed(
				hash_slices(&[
					rcv.hid.as_bytes(),
					rcv.random.as_slice(),
					host_keys.id().as_bytes(),
					self.random.as_slice(),
					secret.as_bytes(),
				])
				.into(),
			),
			cipher: ChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(secret.as_bytes())),
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

struct RngAndCipher {
	other_host_id: Hash,
	nonce_rng_snd: ChaCha20Rng,
	nonce_rng_rcv: ChaCha20Rng,
	cipher: ChaCha20Poly1305,
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

		client.wait_for_conn(Some(HANDSHAKE_TIMEOUT.clone()));
		client.wait_for_exit().unwrap();
	});

	h_thrd_h.join().unwrap();
	c_thrd_h.join().unwrap();
}
