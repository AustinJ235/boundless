use crate::KBMSEvent;
use std::net::UdpSocket;
use std::thread::{self, JoinHandle};

pub struct Client {
	thread: JoinHandle<Result<(), String>>,
}

impl Client {
	pub fn new() -> Self {
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

			let recv_sock = match UdpSocket::bind("0.0.0.0:1026") {
				Ok(ok) => ok,
				Err(e) => return Err(format!("Failed to bind recv socket: {}", e)),
			};

			let send_sock = match UdpSocket::bind("0.0.0.0:0") {
				Ok(ok) => ok,
				Err(e) => return Err(format!("Failed to bind send socket: {}", e)),
			};

			let recv_buffer = [0; 1024];

			Ok(())
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

pub fn client() {
	let socket = UdpSocket::bind("0.0.0.0:1026").unwrap();
	let recv_buffer = [0; 64];
}

pub trait EventReceiver {
	fn send_event(&self, event: KBMSEvent) -> Result<(), String>;
}
