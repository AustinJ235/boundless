use blake3::{hash, Hash};
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use k256::ecdh::EphemeralSecret;
use k256::{EncodedPoint, PublicKey};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use strum::FromRepr;

pub type HostRecvFn = Box<dyn Fn(&Arc<SecureSocketHost>, Hash, PacketType, Vec<u8>) + Send>;
pub type ClientRecvFn = Box<dyn Fn(&Arc<SecureSocketClient>, PacketType, Vec<u8>) + Send>;

#[derive(FromRepr, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum PacketType {
	ClientDH,
	ServerDH,
	ConnTest,
}

pub fn machine_uid() -> Hash {
	hash(&machine_uid::get().unwrap().into_bytes())
}

pub fn hash3(input1: &[u8], input2: &[u8], input3: &[u8]) -> Hash {
	let mut hasher = blake3::Hasher::new();
	hasher.update(input1);
	hasher.update(input2);
	hasher.update(input3);
	hasher.finalize()
}

pub struct SecureSocketHost {
	uid: Hash,
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
		client_uids: Vec<Hash>,
		listen_addr: A,
		recv_fn: HostRecvFn,
	) -> Result<Arc<Self>, String> {
		let listen_addr = listen_addr.to_socket_addrs().unwrap().next().unwrap();
		let socket = UdpSocket::bind(listen_addr.clone())
			.map_err(|e| format!("Failed to bind socket: {}", e))?;

		println!("[Socket-H]: Listening on {:?}", listen_addr);

		let host_ret = Arc::new(Self {
			uid: machine_uid(),
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
							println!("[Socket-H]: Received malformed packet from {:?}", addr);
							continue;
						}

						match PacketType::from_repr(socket_buf[0]) {
							Some(PacketType::ClientDH) => {
								if len != 66 {
									println!(
										"[Socket-H]: Received malformed packet from {:?}",
										addr
									);
									continue;
								}

								let c_uid_b: [u8; 32] =
									(&socket_buf[1..33]).try_into().unwrap();
								let c_uid = Hash::from(c_uid_b);

								if !client_uids.contains(&c_uid) {
									println!(
										"[Socket-H]: Unauthorized connection attempted from \
										 {:?}",
										addr
									);
									continue;
								}

								let c_dh_public =
									match PublicKey::from_sec1_bytes(&socket_buf[33..66]) {
										Ok(ok) => ok,
										Err(_) => {
											println!(
												"[Socket-H]: Received malformed packet from \
												 {:?}",
												addr
											);
											continue;
										},
									};

								let dh_secret = EphemeralSecret::random(&mut OsRng);
								let dh_public = EncodedPoint::from(dh_secret.public_key());
								let secret = hash(
									dh_secret
										.diffie_hellman(&c_dh_public)
										.as_bytes()
										.as_slice(),
								);
								let mut dh_packet = Vec::with_capacity(66);
								dh_packet.push(PacketType::ServerDH as u8);
								dh_packet.extend_from_slice(host.uid.as_bytes());
								dh_packet.extend_from_slice(dh_public.as_bytes());

								if let Err(e) = host.socket.send_to(&dh_packet, addr.clone()) {
									println!(
										"[Socket-H]: Failed to send response to {:?} in DH \
										 exchange: {}",
										addr,
										e.kind()
									);
									continue;
								}

								let nonce_rng_snd = ChaCha20Rng::from_seed(
									hash3(
										host.uid.as_bytes(),
										c_uid.as_bytes(),
										secret.as_bytes(),
									)
									.into(),
								);

								let nonce_rng_rcv = ChaCha20Rng::from_seed(
									hash3(
										c_uid.as_bytes(),
										host.uid.as_bytes(),
										secret.as_bytes(),
									)
									.into(),
								);

								host.clients.lock().insert(c_uid, ClientState {
									addr,
									hs_status: HandshakeStatus::Pending,
									nonce_rng_snd,
									nonce_rng_rcv,
									snd_seq: 0,
									rcv_seq: 0,
									cipher: ChaCha20Poly1305::new(
										chacha20poly1305::Key::from_slice(secret.as_bytes()),
									),
								});

								println!("[Socket-H]: Connection pending with {:?}", addr);
							},
							Some(PacketType::ConnTest) => {
								if len != 153 {
									println!(
										"[Socket-H]: Received malformed packet from {:?}: {} \
										 != 137",
										addr, len
									);
									continue;
								}

								let client_uid_b: [u8; 32] =
									socket_buf[1..33].try_into().unwrap();
								let client_uid: Hash = client_uid_b.into();
								let seq_b: [u8; 8] = socket_buf[33..41].try_into().unwrap();
								let seq = u64::from_le_bytes(seq_b);
								let encrypted_data = &socket_buf[41..len];
								let mut clients = host.clients.lock();

								let mut client_state = match clients.get_mut(&client_uid) {
									Some(some) => some,
									None => {
										println!(
											"[Socket-H]: Received packet from {:?}, but \
											 client is not connected.",
											addr
										);
										continue;
									},
								};

								if seq > client_state.rcv_seq {
									println!(
										"[Socket-H]: Received packet from {:?}, but packet is \
										 late.",
										addr
									);
									continue;
								}

								let mut nonce_bytes = [0_u8; 12];

								while seq < client_state.rcv_seq {
									client_state.nonce_rng_rcv.fill_bytes(&mut nonce_bytes);
									client_state.rcv_seq += 1;
									println!("[Socket-H]: Missing packet from {:?}.", addr);
								}

								client_state.nonce_rng_rcv.fill_bytes(&mut nonce_bytes);
								let nonce = Nonce::from_slice(&nonce_bytes);
								client_state.rcv_seq += 1;

								let decrypted_data =
									match client_state.cipher.decrypt(nonce, encrypted_data) {
										Ok(ok) => ok,
										Err(e) => {
											println!(
												"[Socket-H]: Failed to decrypt packet from \
												 {:?}: {}",
												addr, e
											);
											continue;
										},
									};

								if hash(&decrypted_data[0..64]) != decrypted_data[64..96] {
									println!(
										"[Socket-H]: Connection test failed from {:?}",
										addr
									);
									continue;
								}

								let mut data = Vec::with_capacity(64 + 32);

								for _ in 0..64 {
									data.push(rand::random());
								}

								let hash = hash(&data);
								data.extend_from_slice(hash.as_bytes());

								if let Err(e) = host.send_inner(
									&mut client_state,
									PacketType::ConnTest,
									data,
								) {
									println!(
										"[Socket-H]: Failed to send connection test to {:?}: \
										 {}",
										addr, e
									);
									continue;
								}

								client_state.hs_status = HandshakeStatus::Complete;
								println!("[Socket-H]: Connection established with {:?}", addr);
							},
							_ => {
								println!(
									"[Socket-H]: Received malformed packet from {:?}",
									addr
								);
							},
						}
					},
					Err(e) => println!("[Socket-H]: Failed to receive packet: {}", e.kind()),
				}
			}
		}));

		Ok(host_ret)
	}

	fn send_inner(
		&self,
		client_state: &mut ClientState,
		packet_type: PacketType,
		data: Vec<u8>,
	) -> Result<(), String> {
		let mut send_buf = Vec::with_capacity(1 + 8 + data.len() + 16);
		send_buf.push(packet_type as u8);
		send_buf.extend_from_slice(&client_state.snd_seq.to_le_bytes());

		let mut nonce_b = [0_u8; 12];
		client_state.nonce_rng_snd.fill_bytes(&mut nonce_b);
		client_state.snd_seq += 1;

		let nonce = Nonce::from_slice(&nonce_b);
		let mut encrypted = client_state
			.cipher
			.encrypt(nonce, &*data)
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
	uid: Hash,
	socket: UdpSocket,
	state: Mutex<SSCState>,
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
		host_uid: Hash,
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
		let uid = machine_uid();
		let mut dh_packet = Vec::with_capacity(66);
		dh_packet.push(PacketType::ClientDH as u8);
		dh_packet.extend_from_slice(uid.as_bytes());
		dh_packet.extend_from_slice(dh_public.as_bytes());

		let state = loop {
			match socket.send(&dh_packet) {
				Ok(_) =>
					match socket.recv(&mut dh_packet) {
						Ok(len) => {
							if len != 66 {
								return Err(format!(
									"[Socket-C]: Received malformed packet from host."
								));
							}

							let s_uid_b: [u8; 32] = (&dh_packet[1..33]).try_into().unwrap();
							let s_uid = Hash::from(s_uid_b);

							if host_uid != s_uid {
								return Err(format!(
									"[Socket-C]: Host UID doesn't match provided UID."
								));
							}

							let s_dh_public =
								match PublicKey::from_sec1_bytes(&dh_packet[33..66]) {
									Ok(ok) => ok,
									Err(_) =>
										return Err(format!(
											"[Socket-C]: Received malformed packet from host."
										)),
								};

							let secret = hash(
								dh_secret.diffie_hellman(&s_dh_public).as_bytes().as_slice(),
							);
							let nonce_rng_rcv = ChaCha20Rng::from_seed(
								hash3(s_uid.as_bytes(), uid.as_bytes(), secret.as_bytes())
									.into(),
							);
							let nonce_rng_snd = ChaCha20Rng::from_seed(
								hash3(uid.as_bytes(), s_uid.as_bytes(), secret.as_bytes())
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
										"[Socket-C]: Failed to receive packet: {}",
										e.kind()
									)),
							},
					},
				Err(e) => return Err(format!("[Socket-C]: Failed to send packet: {:?}", e)),
			}
		};

		let client = Arc::new(Self {
			uid,
			socket,
			state: Mutex::new(state),
		});

		let mut data = Vec::with_capacity(64 + 32);

		for _ in 0..64 {
			data.push(rand::random());
		}

		let rand_hash = hash(&data);
		data.extend_from_slice(rand_hash.as_bytes());
		client
			.send(PacketType::ConnTest, data)
			.map_err(|e| format!("[Socket-C]: Connection test failed: {}", e))?;

		{
			let mut state = client.state.lock();
			let mut recv_buf = vec![0_u8; 121];

			let len = client
				.socket
				.recv(&mut recv_buf)
				.map_err(|e| format!("[Socket-C]: Failed to receive packet: {}", e.kind()))?;

			if len != 121 {
				return Err(format!("[Socket-C]: Received malformed packet from host."));
			}

			let packet_type = PacketType::from_repr(recv_buf[0])
				.ok_or(format!("[Socket-C]: Received malformed packet from host."))?;

			if packet_type != PacketType::ConnTest {
				return Err(format!("[Socket-C]: Expected ConnTest packet from host."));
			}

			let seq_b: [u8; 8] = recv_buf[1..9].try_into().unwrap();
			let seq = u64::from_le_bytes(seq_b);

			if state.rcv_seq != 0 || seq != 0 {
				return Err(format!(
					"[Socket-C]: Expected ConnTest packet to be sequence zero."
				));
			}

			let mut nonce_b = [0_u8; 12];
			state.nonce_rng_rcv.fill_bytes(&mut nonce_b);
			state.rcv_seq += 1;

			let nonce = Nonce::from_slice(&nonce_b);
			let decrypted_data = state
				.cipher
				.decrypt(nonce, &recv_buf[9..len])
				.map_err(|e| format!("[Socket-C]: Failed to decrypt packet: {}", e))?;

			if hash(&decrypted_data[0..64]) != decrypted_data[64..96] {
				return Err(format!("[Socket-C]: Connection test failed."));
			}

			println!("[Socket-C]: Connection is established to host.");
		}

		Ok(client)
	}

	pub fn send(&self, packet_type: PacketType, data: Vec<u8>) -> Result<(), String> {
		let mut state = self.state.lock();
		let mut send_buf = Vec::with_capacity(57 + data.len());
		send_buf.push(packet_type as u8);
		send_buf.extend_from_slice(self.uid.as_bytes());
		send_buf.extend_from_slice(&state.snd_seq.to_le_bytes());

		let mut nonce_b = [0_u8; 12];
		state.nonce_rng_snd.fill_bytes(&mut nonce_b);
		state.snd_seq += 1;

		let nonce = Nonce::from_slice(&nonce_b);
		let mut encrypted = state
			.cipher
			.encrypt(nonce, &*data)
			.map_err(|e| format!("Failed to encrypt payload: {}", e))?;
		send_buf.append(&mut encrypted);

		match self.socket.send(&*send_buf) {
			Ok(_) => Ok(()), // TODO: what if len != sent?
			Err(e) => Err(format!("Failed to send packet: {}", e)),
		}
	}
}

/*#[test]
fn test() {
	use std::thread;

	let h_thrd_h = thread::spawn(move || {
		let host = SecureSocketHost::listen(
			vec![machine_uid()],
			"0.0.0.0:1026",
			Box::new(move |_host, _client_uid, _packet_type, _packet_data| {}),
		)
		.unwrap();

		host.wait_for_exit().unwrap();
	});

	let c_thrd_h = thread::spawn(move || {
		let _client = SecureSocketClient::connect(
			machine_uid(),
			"127.0.0.1:1026",
			Box::new(move |_client, _packet_type, _packet_data| {}),
		)
		.unwrap();
	});

	h_thrd_h.join().unwrap();
	c_thrd_h.join().unwrap();
}*/