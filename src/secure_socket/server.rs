use super::{
	CryptoError, CryptoState, ECDHRcv, ECDHSnd, HostID, PacketType, SSSOnConnect, SSSOnDisconnect, SSSRecvFn,
	SendError, CLIENTS_CHECK_INTERVAL, HANDSHAKE_DISCONNECT, HANDSHAKE_TIMEOUT, PING_DISCONNECT,
};
use crate::host_keys::HostKeys;
use blake3::{hash, Hash};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::Rng;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub struct SecureSocketServer {
	host_keys: HostKeys,
	socket: UdpSocket,
	clients: Mutex<HashMap<HostID, ClientState>>,
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

		let server_ret = Arc::new(Self {
			host_keys,
			socket,
			clients: Mutex::new(HashMap::new()),
			thrd_recv_h: Mutex::new(None),
		});

		let server_wk = Arc::downgrade(&server_ret);

		*server_ret.thrd_recv_h.lock() = Some(thread::spawn(move || {
			let mut socket_buf = vec![0_u8; 65535];
			let mut last_clients_check = Instant::now();

			loop {
				let server = match server_wk.upgrade() {
					Some(some) => some,
					None => return,
				};

				if last_clients_check.elapsed() > CLIENTS_CHECK_INTERVAL {
					let mut call_disconnect = Vec::new();

					server.clients.lock().retain(|client_id, client_state| {
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
						on_disconnect(&server, client_id);
					}

					last_clients_check = Instant::now();
				}

				match server.socket.recv_from(&mut *socket_buf) {
					Ok((len, addr)) => {
						if len < 1 {
							continue;
						}

						match PacketType::from_repr(socket_buf[0]) {
							Some(packet_type) => {
								if packet_type == PacketType::ECDH {
									let ecdh_rcv = match ECDHRcv::new(&server.host_keys, &socket_buf[0..len]) {
										Ok(ok) => ok,
										Err(e) => {
											println!(
												"[Socket-H]: Rejected connection from {:?}, reason: {}",
												addr, e
											);
											continue;
										},
									};

									let ecdh_snd = ECDHSnd::new(&server.host_keys);

									if let Err(e) = server.socket.send_to(ecdh_snd.packet.as_slice(), addr.clone())
									{
										println!(
											"[Socket-H]: Rejected connection from {:?}: reason: send error: {}",
											addr,
											e.kind()
										);
										continue;
									}

									let client_id = ecdh_rcv.hid.clone();
									let crypto = ecdh_snd.handshake(&server.host_keys, ecdh_rcv);

									server.clients.lock().insert(client_id, ClientState {
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
								let c_id = HostID::from(c_id_b);
								let seq_b: [u8; 8] = socket_buf[33..41].try_into().unwrap();
								let seq = u64::from_le_bytes(seq_b);
								let mut clients = server.clients.lock();

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
										on_disconnect(&server, c_id);
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
											server.send_internal(&mut client_state, PacketType::Verify, r_msg)
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
										on_connect(&server, c_id);
										println!("[Socket-H]: Connection established with {:?}", addr);
									},
									PacketType::Ping => {
										if let Err(e) =
											server.send_internal(&mut client_state, PacketType::Ping, Vec::new())
										{
											println!("[Socket-H]: Failed to response ping to {:?}: {}", addr, e);
											continue;
										}

										client_state.ping_recv = Instant::now();
									},
									PacketType::Message => {
										drop(client_state);
										drop(clients);
										recv_fn(&server, c_id, msg);
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
							std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => (),
							kind => println!("[Socket-H]: Failed to receive packet: {}", kind),
						},
				}
			}
		}));

		Ok(server_ret)
	}

	pub fn send(&self, client_id: HostID, data: Vec<u8>) -> Result<(), SendError> {
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
