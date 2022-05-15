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
		let socket = UdpSocket::bind(listen_addr.clone())
			.map_err(|e| format!("Failed to bind socket: {}", e))?;
		socket.set_read_timeout(Some(Duration::from_millis(500))).unwrap();

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
											"[Socket-H]: Rejected connection from {:?}, \
											 reason: packet truncated",
											addr
										);
										continue;
									}

									let c_id_b: [u8; 32] =
										(&socket_buf[1..33]).try_into().unwrap();
									let c_id = Hash::from(c_id_b);
									let sig_len = socket_buf[33] as usize;
									let sig_end = 34 + sig_len;

									if sig_end > len {
										println!(
											"[Socket-H]: Rejected connection from {:?}, \
											 reason: signature truncated",
											addr
										);
										continue;
									}

									let sig_b = &socket_buf[34..sig_end];
									let msg_end = sig_end as usize + 64;

									if msg_end > len {
										println!(
											"[Socket-H]: Rejected connection from {:?}, \
											 reason: message truncated",
											addr
										);
										continue;
									}

									let msg = &socket_buf[sig_end..msg_end];

									if let Err(e) =
										host.host_keys.verify_message(c_id, sig_b, msg)
									{
										println!(
											"[Socket-H]: Rejected connection from {:?}, \
											 reason: {}",
											addr, e
										);
										continue;
									}

									let c_dh_pub_len = msg[0] as usize;

									if c_dh_pub_len > 63 {
										println!(
											"[Socket-H]: Rejected connection from {:?}, \
											 reason: publick key truncated",
											addr
										);
										continue;
									}

									let c_dh_pub = match PublicKey::from_sec1_bytes(
										&msg[1..(1 + c_dh_pub_len)],
									) {
										Ok(ok) => ok,
										Err(_) => {
											println!(
												"[Socket-H]: Rejected connection from {:?}, \
												 reason: invalid public key",
												addr
											);
											continue;
										},
									};

									let c_random = &msg[(1 + c_dh_pub_len)..64];
									let dh_secret = EphemeralSecret::random(&mut OsRng);
									let dh_public = EncodedPoint::from(dh_secret.public_key());
									let secret = hash(
										dh_secret
											.diffie_hellman(&c_dh_pub)
											.as_bytes()
											.as_slice(),
									);

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
									ecdh_buf
										.append(&mut host.host_keys.sign_message(&ecdh_data));
									ecdh_buf[33] = (ecdh_buf.len() - 34) as u8;
									ecdh_buf.append(&mut ecdh_data);

									if let Err(e) = host.socket.send_to(&ecdh_buf, addr.clone())
									{
										println!(
											"[Socket-H]: Rejected connection from {:?}: \
											 reason: send error: {}",
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
										cipher: ChaCha20Poly1305::new(
											chacha20poly1305::Key::from_slice(
												secret.as_bytes(),
											),
										),
									});

									println!("[Socket-H]: Connection pending with {:?}", addr);
									continue;
								}

								if len < 129 {
									println!(
										"[Socket-H]: Rejected packet from {:?}, reason: \
										 truncated",
										addr
									);
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
											"[Socket-H]: Rejected packet from {:?}, reason: \
											 not connected",
											addr
										);
										continue;
									},
								};

								if seq > client_state.rcv_seq {
									println!(
										"[Socket-H]: Rejected packet from {:?}, reason: late",
										addr
									);
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
									println!(
										"[Socket-H]: Detected {} dropped packets from {:?}",
										dropped, addr
									);
								}

								client_state.nonce_rng_rcv.fill_bytes(&mut nonce_b);
								let nonce = Nonce::from_slice(&nonce_b);
								client_state.rcv_seq += 1;

								let decrypted =
									match client_state.cipher.decrypt(nonce, encrypted) {
										Ok(ok) => ok,
										Err(e) => {
											println!(
												"[Socket-H]: Rejected packet from {:?}, \
												 reason: encryption error: {}",
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
										"[Socket-H]: Rejected packet from {:?}, reason: \
										 invalid message length",
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
												"[Socket-H]: Rejected connection from {:?}, \
												 reason: verify length mismatch",
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
												"[Socket-H]: Rejected connection from {:?}, \
												 reason: verify hash mismatch",
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

										if let Err(e) = host.send_inner(
											&mut client_state,
											PacketType::Verify,
											r_msg,
										) {
											println!(
												"[Socket-H]: Rejected connection from {:?}, \
												 reason: verify send error: {}",
												addr, e
											);
											drop(client_state);
											clients.remove(&c_id);
											continue;
										}

										client_state.hs_status = HandshakeStatus::Complete;
										println!(
											"[Socket-H]: Connection established with {:?}",
											addr
										);
									},
									PacketType::Ping => {
										if let Err(e) = host.send_inner(
											&mut client_state,
											PacketType::Ping,
											Vec::new(),
										) {
											println!(
												"[Socket-H]: Failed to response ping to {:?}: \
												 {}",
												addr, e
											);
										}
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
									"[Socket-H]: Rejected packet from {:?}, reason: invalid \
									 packet type",
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

	pub fn send(&self, client_id: Hash, data: Vec<u8>) -> Result<(), String> {
		let mut clients = self.clients.lock();
		let mut client_state =
			clients.get_mut(&client_id).ok_or(String::from("Client not connected."))?;
		self.send_inner(&mut client_state, PacketType::Message, data)
	}

	fn send_inner(
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
			Err(e) =>
				Err(format!("Failed to send packet to {:?}: {}", client_state.addr, e.kind())),
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
	state: Mutex<SSCState>,
	thrd_recv_h: Mutex<Option<JoinHandle<()>>>,
	ping_cond: Condvar,
	ping_recv: Mutex<bool>,
}

struct SSCState {
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
		let socket = UdpSocket::bind("0.0.0.0:0")
			.map_err(|e| format!("Failed to bind socket: {}", e))?;
		socket.connect(host_addr.clone()).unwrap();
		socket.set_read_timeout(Some(Duration::from_millis(500))).unwrap();

		println!(
			"[Socket-C]: Listening on {:?}, Connecting to {:?}",
			socket.local_addr().unwrap(),
			host_addr
		);

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
		ecdh_buf.extend_from_slice(host_keys.id().as_bytes());
		ecdh_buf.push(0);
		ecdh_buf.append(&mut host_keys.sign_message(&ecdh_data));
		ecdh_buf[33] = (ecdh_buf.len() - 34) as u8;
		ecdh_buf.append(&mut ecdh_data);

		let mut socket_buf = vec![0_u8; 65535];

		let state = loop {
			match socket.send(&ecdh_buf) {
				Ok(_) =>
					match socket.recv(&mut socket_buf) {
						Ok(len) => {
							if len < 35 {
								return Err(String::from(
									"Connection failed: invalid packet length",
								));
							}

							match PacketType::from_repr(socket_buf[0]) {
								Some(PacketType::ECDH) => (),
								Some(_) | None =>
									return Err(String::from(
										"Connection failed: invalid packet type",
									)),
							}

							let h_id_b: [u8; 32] = socket_buf[1..33].try_into().unwrap();
							let h_id = Hash::from(h_id_b);
							let sig_len = socket_buf[33] as usize;
							let sig_end = 34 + sig_len;

							if sig_end > len {
								return Err(String::from(
									"Connection failed: malformed packet",
								));
							}

							let sig_b = &socket_buf[34..sig_end];
							let msg_end = sig_end + 64;

							if msg_end > len {
								return Err(String::from(
									"Connection failed: malformed packet",
								));
							}

							let msg = &socket_buf[sig_end..msg_end];
							host_keys.verify_message(h_id, sig_b, msg).map_err(|e| {
								format!("Connection failed: message verification error: {}", e)
							})?;
							let h_dh_pub_len = msg[0] as usize;

							if h_dh_pub_len > 63 {
								return Err(String::from(
									"Connection failed: malformed packet",
								));
							}

							let h_dh_pub =
								PublicKey::from_sec1_bytes(&msg[1..(1 + h_dh_pub_len)])
									.map_err(|_| {
										String::from("Connection failed: invalid public key")
									})?;
							let h_random = &msg[(1 + h_dh_pub_len)..64];
							let secret =
								hash(dh_secret.diffie_hellman(&h_dh_pub).as_bytes().as_slice());

							let nonce_rng_rcv = ChaCha20Rng::from_seed(
								hash_slices(&[
									h_id.as_bytes(),
									h_random,
									host_keys.id().as_bytes(),
									&c_random,
									secret.as_bytes(),
								])
								.into(),
							);

							let nonce_rng_snd = ChaCha20Rng::from_seed(
								hash_slices(&[
									host_keys.id().as_bytes(),
									&c_random,
									h_id.as_bytes(),
									h_random,
									secret.as_bytes(),
								])
								.into(),
							);

							break SSCState {
								nonce_rng_rcv,
								nonce_rng_snd,
								snd_seq: 0,
								rcv_seq: 0,
								cipher: ChaCha20Poly1305::new(
									chacha20poly1305::Key::from_slice(secret.as_bytes()),
								),
							};
						},
						Err(e) =>
							match e.kind() {
								std::io::ErrorKind::TimedOut => {
									println!("[Socket-C]: No response from server.");
									thread::sleep(Duration::from_millis(500));
									continue;
								},
								_ =>
									return Err(format!(
										"Connection failed: receive error: {}",
										e.kind()
									)),
							},
					},
				Err(e) => return Err(format!("Connection failed: send error: {}", e.kind())),
			}
		};

		let client_ret = Arc::new(Self {
			host_keys,
			socket,
			state: Mutex::new(state),
			thrd_recv_h: Mutex::new(None),
			ping_cond: Condvar::new(),
			ping_recv: Mutex::new(false),
		});

		let client = client_ret.clone();

		// Verify Send
		let mut rand_data = [0_u8; 32];
		OsRng::fill(&mut OsRng, &mut rand_data);
		let rand_hash = hash(&rand_data);
		let mut r_msg = Vec::with_capacity(64);
		r_msg.extend_from_slice(&rand_data);
		r_msg.extend_from_slice(rand_hash.as_bytes());
		client
			.send_inner(PacketType::Verify, r_msg)
			.map_err(|e| format!("Connection Failed: send error: {}", e))?;

		// Verify Receive
		{
			let (packet_type, msg) = match client.recv_message(&mut socket_buf) {
				Ok(ok) =>
					match ok {
						Some(some) => some,
						None =>
							return Err(String::from("Connection failed: receive timed out")),
					},
				Err(e) => return Err(format!("Connection failed: receive error: {}", e)),
			};

			if packet_type != PacketType::Verify {
				return Err(String::from("received wrong packet type"));
			}

			if msg.len() != 64 {
				return Err(String::from("verify length mismatch"));
			}

			let msg_h_b: [u8; 32] = msg[32..64].try_into().unwrap();
			let msg_h = Hash::from(msg_h_b);

			if msg_h != hash(&msg[0..32]) {
				return Err(String::from("verify hash mismatch"));
			}
		}

		*client_ret.thrd_recv_h.lock() = Some(thread::spawn(move || {
			loop {
				match client.recv_message(&mut socket_buf) {
					Ok(ok) =>
						match ok {
							Some((packet_type, data)) =>
								match packet_type {
									PacketType::ECDH => unreachable!(),
									PacketType::Verify => {
										// Probably unreachable? but not panic worthy
										println!("[Socket-C]: Unexpected Verify!");
									},
									PacketType::Ping => {
										*client.ping_recv.lock() = true;
										client.ping_cond.notify_one();
									},
									PacketType::Message => recv_fn(&client, data),
								},
							None => (), // Timed Out
						},
					Err(e) => println!("[Socket-C]: Failed to receive packet: {}", e),
				}
			}
		}));

		println!("[Socket-C]: Connection is established to host.");
		Ok(client_ret)
	}

	pub fn ping(&self) -> Result<Duration, String> {
		let start = Instant::now();
		self.send_inner(PacketType::Ping, Vec::new())?;
		let mut ping_recv = self.ping_recv.lock();
		self.ping_cond.wait_for(&mut ping_recv, Duration::from_millis(1000));

		if !*ping_recv {
			Err(format!("No response"))
		} else {
			*ping_recv = false;
			Ok(start.elapsed())
		}
	}

	fn recv_message(
		&self,
		socket_buf: &mut [u8],
	) -> Result<Option<(PacketType, Vec<u8>)>, String> {
		let len = match self.socket.recv(socket_buf) {
			Ok(ok) => ok,
			Err(e) =>
				match e.kind() {
					std::io::ErrorKind::TimedOut => return Ok(None),
					kind => return Err(format!("receive error: {}", kind)),
				},
		};

		if len < 129 {
			return Err(String::from("packet truncated"));
		}

		let packet_type = match PacketType::from_repr(socket_buf[0]) {
			Some(PacketType::ECDH) | None => return Err(String::from("invalid packet type")),
			Some(some) => some,
		};

		let h_id_b: [u8; 32] = socket_buf[1..33].try_into().unwrap();
		let _h_id = Hash::from(h_id_b);
		let seq_b: [u8; 8] = socket_buf[33..41].try_into().unwrap();
		let seq = u64::from_le_bytes(seq_b);
		let encrypted = &socket_buf[41..len];
		let mut client_state = self.state.lock();

		if seq > client_state.rcv_seq {
			return Err(format!("packet late"));
		}

		let mut nonce_b = [0_u8; 12];
		let mut dropped = 0_usize;

		while seq < client_state.rcv_seq {
			client_state.nonce_rng_rcv.fill_bytes(&mut nonce_b);
			client_state.rcv_seq += 1;
			dropped += 1;
		}

		if dropped > 0 {
			println!("[Socket-C]: Detected {} dropped packets from host.", dropped);
		}

		client_state.nonce_rng_rcv.fill_bytes(&mut nonce_b);
		let nonce = Nonce::from_slice(&nonce_b);
		client_state.rcv_seq += 1;

		let decrypted = client_state
			.cipher
			.decrypt(nonce, encrypted)
			.map_err(|e| format!("encryption error: {}", e))?;

		assert!(decrypted.len() >= 72);
		let msg_len_b: [u8; 8] = decrypted[0..8].try_into().unwrap();
		let msg_len = u64::from_le_bytes(msg_len_b) as usize;

		if msg_len > decrypted.len() + 8 {
			return Err(format!("length mismatch"));
		}

		let msg = decrypted[8..(8 + msg_len)].to_vec();
		Ok(Some((packet_type, msg)))
	}

	pub fn send(&self, data: Vec<u8>) -> Result<(), String> {
		self.send_inner(PacketType::Message, data)
	}

	fn send_inner(&self, packet_type: PacketType, mut data: Vec<u8>) -> Result<(), String> {
		let mut client_state = self.state.lock();
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
		let start = Instant::now();
		let client = SecureSocketClient::connect(
			c_host_keys,
			"127.0.0.1:1026",
			Box::new(move |_client, _packet_data| {}),
		)
		.unwrap();

		println!("[Socket-C]: Initialization done in {0:.2} ms", start.elapsed().as_micros() as f32 / 1000.0);

		for _ in 0..10 {
			match client.ping() {
				Ok(ok) => println!("[Socket-C]: Ping to Host: {:.2} ms", ok.as_micros() as f32 / 1000.0),
				Err(e) => println!("[Socket-C]: Ping to Host Failed: {}", e),
			}

			thread::sleep(Duration::from_millis(rand::random::<u8>() as u64 * 4));
		}

		client.wait_for_exit().unwrap();
	});

	h_thrd_h.join().unwrap();
	c_thrd_h.join().unwrap();
}
