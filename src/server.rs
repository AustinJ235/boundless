use crate::KBMSEvent;
use atomicring::AtomicRingQueue;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub struct Server {
	thread: JoinHandle<Result<(), String>>,
}

impl Server {
	pub fn new() -> Self {
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

			let socket = UdpSocket::bind("0.0.0.0:1026")
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
										KBMSEvent::Hello => {
											match socket.send_to(&socket_buf, &from) {
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
												KBMSEvent::Hello => {
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

pub trait Capture {
	fn event_queue(&self) -> &AtomicRingQueue<KBMSEvent>;
}
