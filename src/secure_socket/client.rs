use super::{
	CryptoError, CryptoState, ECDHRcv, ECDHSnd, HostID, PacketType, SSCOnConnect, SSCOnDisconnect, SSCRecvFn,
	SendError, HANDSHAKE_INTERVAL, HANDSHAKE_TIMEOUT, PING_DISCONNECT, PING_INTERVAL,
};
use crate::host_keys::HostKeys;
use blake3::{hash, Hash};
use parking_lot::{Condvar, Mutex};
use rand::rngs::OsRng;
use rand::Rng;
use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

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

		let client_wk = Arc::downgrade(&client_ret);

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
				let client = match client_wk.upgrade() {
					Some(some) => some,
					None => return,
				};

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
										let h_id = HostID::from(h_id_b);

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
												ping_recv = Instant::now();
												client.conn_cond.notify_all();
												drop(client_state);
												drop(client_state_gu);
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
							std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock =>
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
