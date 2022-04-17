use crate::KBMSEvent;
use atomicring::AtomicRingQueue;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub struct Server {
	thread: JoinHandle<Result<(), String>>,
}

impl Server {
	pub fn new() -> Self {
		let thread = thread::spawn(move || {
			let capture_result: Result<Box<dyn Capture>, String> = {
				#[cfg(target_os = "windows")]
				{
					crate::windows::WindowsCapture::new()
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

			loop {
				if current_client.is_none() {
					capture.event_queue().clear();
					seq = 0;

					match socket.recv_from(&mut socket_buf) {
						Ok((len, from)) =>
							match KBMSEvent::decode(&socket_buf[0..len]) {
								Some((_, event)) =>
									match event {
										KBMSEvent::Hello => {
											match socket.send_to(&socket_buf, &from) {
												Ok(_) => current_client = Some(from),
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
								io::ErrorKind::TimedOut => continue,
								e => return Err(format!("Failed to read from socket: {}", e)),
							},
					}
				} else {
					capture.event_queue().clear();
					seq = 0;
					println!("I have a client!");
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
