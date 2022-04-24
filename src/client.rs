use crate::KBMSEvent;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub struct Client {
	thread: JoinHandle<Result<(), String>>,
}

impl Client {
	pub fn new(connect_to: SocketAddr) -> Self {
		let thread = thread::spawn(move || {
			let event_receiver_result: Result<Box<dyn EventReceiver>, String> = {
				#[cfg(target_family = "unix")]
				{
					crate::platform::uinput::UInputEventReceiver::new()
				}
				#[cfg(not(target_family = "unix"))]
				{
					Err(String::from("Platform not supported."))
				}
			};

			let event_receiver = match event_receiver_result {
				Ok(ok) => ok,
				Err(e) => return Err(format!("Failed to initialize event receiver: {}", e)),
			};

			let socket = match UdpSocket::bind(connect_to) {
				Ok(ok) => ok,
				Err(e) => return Err(format!("Failed to bind recv socket: {}", e)),
			};

			let mut socket_buf = [0_u8; 32];
			let mut last_conn_check;
			let conn_check_interval_max = Duration::from_secs(7);
			socket.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
			socket.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
			socket.connect("192.168.1.235:1026").unwrap();

			'connection: loop {
				println!("Sending Hello...");

				if let Err(e) = socket.send(&KBMSEvent::Hello.encode(0)) {
					println!("Failed to send Hello: {}", e);
					continue;
				}

				match socket.recv(&mut socket_buf) {
					Ok(len) =>
						match KBMSEvent::decode(&socket_buf[0..len]) {
							Some((_, some)) =>
								match some {
									KBMSEvent::Hello => (),
									event => {
										println!(
											"Unexpected response from server {:?} expected \
											 {:?}",
											event,
											KBMSEvent::Hello
										);
										continue;
									},
								},
							None => {
								println!("Failed to decode packet from server.");
								continue;
							},
						},
					Err(e) =>
						match e.kind() {
							io::ErrorKind::WouldBlock => {
								println!("No response from server.");
								continue;
							},
							e =>
								return Err(format!(
									"Unexpected error attempted to receiver from socket: \
									 {:?}({})",
									e, e
								)),
						},
				}

				println!("Connected to server.");
				last_conn_check = Instant::now();

				loop {
					let len = match socket.recv(&mut socket_buf) {
						Ok(ok) => ok,
						Err(e) =>
							match e.kind() {
								io::ErrorKind::WouldBlock => {
									if last_conn_check.elapsed() > conn_check_interval_max {
										println!("Connection to server has been lost.");
										continue 'connection;
									}

									continue;
								},
								e => {
									println!(
										"Unexpected error attempted to receiver from socket: \
										 {:?}({})",
										e, e
									);
									continue 'connection;
								},
							},
					};

					match KBMSEvent::decode(&socket_buf[0..len]) {
						Some((_seq, event)) => {
							match &event {
								KBMSEvent::ConnectionCheck =>
									match socket.send(&KBMSEvent::Hello.encode(0)) {
										Ok(_) => {
											println!("Connection check succeeded.");
											last_conn_check = Instant::now();
											continue;
										},
										Err(e) => {
											println!(
												"Failed to send Hello in response to \
												 connection check: {}",
												e
											);
											continue 'connection;
										},
									},
								_ => (),
							}

							if let Err(e) = event_receiver.send_event(event) {
								println!("Failed to write event: {}", e);
							}
						},
						None => println!("Failed to decode packet from server."),
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

pub trait EventReceiver {
	fn send_event(&self, event: KBMSEvent) -> Result<(), String>;
}
