use crate::{AudioStreamInfo, KBMSEvent};
use atomicring::AtomicRingQueue;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub trait Capture {
	fn event_queue(&self) -> &AtomicRingQueue<KBMSEvent>;
}

pub trait AudioPlayback {
	// Ok(true) if queue was overwritten, Ok(false) if queue wasn't full, Err if the thread has
	// exited.
	fn push_chunk(&self, chunk: Vec<f32>) -> Result<bool, ()>;
	// Err if the thread has exited.
	fn stream_info(&self) -> Result<AudioStreamInfo, ()>;
	fn exit(self) -> Result<(), String>;
}

pub struct Server {
	thread: JoinHandle<Result<(), String>>,
}

impl Server {
	pub fn new(bind_to: SocketAddr, audio_enable: bool) -> Self {
		let thread = thread::spawn(move || -> Result<(), String> {
			let capture_result: Result<Box<dyn Capture>, String> = {
				#[cfg(target_os = "windows")]
				{
					crate::platform::windows::WindowsCapture::new()
				}
				#[cfg(not(target_os = "windows"))]
				{
					Err(String::from("Platform not supported."))
				}
			};

			let capture = match capture_result {
				Ok(ok) => ok,
				Err(e) => return Err(format!("Failed to initiate capture: {}", e)),
			};

			let socket = UdpSocket::bind(bind_to)
				.map_err(|e| format!("Failed to bind socket: {}", e))?;
			socket
				.set_read_timeout(Some(Duration::from_millis(500)))
				.map_err(|e| format!("Failed to set read timeout: {}", e))?;
			socket
				.set_write_timeout(Some(Duration::from_millis(500)))
				.map_err(|e| format!("Failed to set read timeout: {}", e))?;

			let mut current_client: Option<SocketAddr> = None;
			let mut seq: u128 = 0;
			let mut socket_buf = [0_u8; 32];
			let mut last_conn_check = Instant::now();
			let conn_check_interval = Duration::from_secs(5);
			let queue_pop_timeout = Duration::from_secs(1);

			let audio_port = if audio_enable {
				let audio_res: Result<Box<dyn AudioPlayback + Send>, String> = {
					#[cfg(target_os = "windows")]
					{
						crate::platform::wasapi::WASAPIPlayback::new()
					}
					#[cfg(not(target_os = "windows"))]
					{
						Err(String::from("Platform not supported."))
					}
				};

				let audio = audio_res
					.map_err(|e| format!("Failed to initiate audio playback: {}", e))?;
				let audio_socket = UdpSocket::bind("0.0.0.0:0")
					.map_err(|e| format!("Failed to bind audio socket: {}", e))?;
				let audio_port = audio_socket
					.local_addr()
					.map_err(|e| format!("Failed to obtain port for audio socket: {}", e))?
					.port() as u32;

				thread::spawn(move || {
					let mut socket_buf = vec![0_u8; 65535];

					loop {
						match audio_socket.recv_from(socket_buf.as_mut_slice()) {
							Ok((len, _)) => {
								let mut audio_chunk = Vec::with_capacity(len / 4);

								for sample_bytes in socket_buf[0..len].chunks_exact(4) {
									audio_chunk.push(f32::from_le_bytes([
										sample_bytes[0],
										sample_bytes[1],
										sample_bytes[2],
										sample_bytes[3],
									]));
								}

								match audio.push_chunk(audio_chunk) {
									Ok(overwritten) =>
										if overwritten {
											println!(
												"[Audio]: Incoming data overwrote data. \
												 Playback buffer is full."
											);
										},
									Err(_) => {
										// TODO: call exit() somehow
										println!("[Audio]: Playback thread has exited.");
										return;
									},
								}
							},
							Err(_) => (),
						}
					}
				});

				Some(audio_port)
			} else {
				None
			};

			'client_check: loop {
				if current_client.is_none() {
					println!("Looking for client...");

					// If the queue ever fills windows will start to spin
					capture.event_queue().clear();
					seq = 0;

					match socket.recv_from(&mut socket_buf) {
						Ok((len, from)) =>
							match KBMSEvent::decode(&socket_buf[0..len]) {
								Some((_, event)) =>
									match event {
										KBMSEvent::ClientInfo {
											audio,
										} => {
											let audio_port = match audio {
												true =>
													match audio_enable {
														true => audio_port,
														false => None,
													},
												false => None,
											};

											match socket.send_to(
												&KBMSEvent::ServerInfo {
													audio_port,
												}
												.encode(0),
												&from,
											) {
												Ok(_) => {
													current_client = Some(from);
													last_conn_check = Instant::now();
													// Make sure client isn't flooded with input
													// when they first connect
													capture.event_queue().clear();
													println!("Client has connected.");
												},
												Err(e) =>
													println!(
														"Client attempted to connect, but \
														 didn't respond back: {}",
														e
													),
											}
										},
										_ =>
											println!(
												"Client attempted to connect, but didn't say \
												 hello."
											),
									},
								None =>
									println!("Client attempted to connect, but sent gibberish."),
							},
						Err(e) =>
							match e.kind() {
								io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => continue,
								e => return Err(format!("Failed to read from socket: {}", e)),
							},
					}
				} else {
					if last_conn_check.elapsed() >= conn_check_interval {
						let event_b = KBMSEvent::ConnectionCheck.encode(seq);
						seq += 1;

						if let Err(e) =
							socket.send_to(&event_b, current_client.as_ref().unwrap())
						{
							println!("Failed to send connection check to client: {}", e);
							current_client = None;
							continue;
						}

						loop {
							match socket.recv_from(&mut socket_buf) {
								Ok((len, from)) => {
									if *current_client.as_ref().unwrap() != from {
										continue;
									}

									match KBMSEvent::decode(&socket_buf[0..len]) {
										Some((_, event)) =>
											match event {
												KBMSEvent::ConnectionGood => {
													println!("Connection check succeeded.");
													last_conn_check = Instant::now();
													break;
												},
												_ => {
													println!(
														"Client failed connection check. \
														 Received wrong response."
													);
													current_client = None;
													continue 'client_check;
												},
											},
										None => {
											println!(
												"Client failed connection check. Failed to \
												 decode event."
											);
											current_client = None;
											continue 'client_check;
										},
									}
								},
								Err(e) => {
									println!(
										"Client failed connection check. Socket receive \
										 error: {}",
										e
									);
									current_client = None;
									continue 'client_check;
								},
							}
						}
					}

					let event_b = match capture.event_queue().pop_for(queue_pop_timeout.clone())
					{
						Some(event) => {
							let bytes = event.encode(seq);
							seq += 1;
							bytes
						},
						None => continue,
					};

					if let Err(_) = socket.send_to(&event_b, current_client.as_ref().unwrap()) {
						println!(
							"Failed to send message to client. Looking for new connection."
						);
						current_client = None;
						continue;
					}
				}
			}
		});

		Self {
			thread,
		}
	}

	pub fn wait_for_exit(self) -> Result<(), String> {
		match self.thread.join() {
			Ok(ok) => ok,
			Err(_) => Err(String::from("thread panicked")),
		}
	}
}
