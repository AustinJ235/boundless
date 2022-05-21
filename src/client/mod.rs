pub mod backend;

use self::backend::{new_audio_source, new_input_endpoint, AudioSource, InputEndpoint};
use crate::host_keys::HostKeys;
use crate::message::Message;
use crate::secure_socket::{SSCOnConnect, SSCOnDisconnect, SSCRecvFn, SecureSocketClient};
use crate::worm::Worm;
use parking_lot::{Condvar, Mutex};
use std::net::SocketAddr;
use std::sync::atomic::{self, AtomicBool};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub struct Client {
	socket: Arc<SecureSocketClient>,
	input_endpoint: Box<dyn InputEndpoint + Send + Sync>,
	audio_source: Option<Box<dyn AudioSource + Send + Sync>>,
	audio_snd_h: Option<JoinHandle<()>>,
	error: Mutex<Option<String>>,
	error_cond: Condvar,
	send_audio: AtomicBool,
}

impl Client {
	pub fn new(connect_to: SocketAddr, audio_enable: bool) -> Result<Arc<Worm<Self>>, String> {
		let client: Arc<Worm<Client>> = Arc::new(Worm::new());
		let host_keys = HostKeys::load()?;
		let input_endpoint =
			new_input_endpoint().map_err(|e| format!("Failed to initialize input endpoint: {}", e))?;

		let audio_source = match audio_enable {
			true => Some(new_audio_source().map_err(|e| format!("Failed to initialize audio source: {}", e))?),
			false => None,
		};

		let client_wk = Arc::downgrade(&client);
		let on_receive: SSCRecvFn = Box::new(move |_, data| {
			match client_wk.upgrade() {
				Some(client_worm) =>
					match client_worm.blocking_read_timeout(Duration::from_millis(500)) {
						Ok(client) => client.on_receive(data),
						Err(_) => return,
					},
				None => return,
			}
		});

		let client_wk = Arc::downgrade(&client);
		let on_connect: SSCOnConnect = Box::new(move |_| {
			match client_wk.upgrade() {
				Some(client_worm) =>
					match client_worm.blocking_read_timeout(Duration::from_millis(500)) {
						Ok(client) => client.on_connect(),
						Err(_) => return,
					},
				None => return,
			}
		});

		let client_wk = Arc::downgrade(&client);
		let on_disconnect: SSCOnDisconnect = Box::new(move |_| {
			match client_wk.upgrade() {
				Some(client_worm) =>
					match client_worm.blocking_read_timeout(Duration::from_millis(500)) {
						Ok(client) => client.on_disconnect(),
						Err(_) => return,
					},
				None => return,
			}
		});

		let socket = SecureSocketClient::connect(host_keys, connect_to, on_receive, on_connect, on_disconnect)?;
		let client_wk = Arc::downgrade(&client);

		let audio_snd_h = if audio_enable {
			Some(thread::spawn(move || {
				loop {
					let worm = match client_wk.upgrade() {
						Some(worm) => worm,
						None => return,
					};

					let client = match worm.blocking_read_timeout(Duration::from_millis(500)) {
						Ok(ok) => ok,
						Err(_) => return,
					};

					match client.audio_source.as_ref().unwrap().next_message(Some(Duration::from_millis(500))) {
						Ok(message_op) =>
							if let Some(message) = message_op {
								if client.send_audio.load(atomic::Ordering::SeqCst) {
									client.send_message(message);
								}
							},
						Err(e) => {
							client.signal_error(format!("Failed to receive audio: {}", e));
							break;
						},
					}
				}
			}))
		} else {
			None
		};

		client.write(Client {
			socket,
			input_endpoint,
			audio_source,
			audio_snd_h,
			error: Mutex::new(None),
			error_cond: Condvar::new(),
			send_audio: AtomicBool::new(false),
		});

		Ok(client)
	}

	fn on_connect(&self) {
		self.send_message(Message::Support {
			audio: self.audio_source.is_some(),
		});
	}

	fn on_disconnect(&self) {
		self.send_audio.store(false, atomic::Ordering::SeqCst);
	}

	fn on_receive(&self, data: Vec<u8>) {
		match Message::decode(data) {
			Some(message) =>
				match message {
					Message::Support {
						audio,
					} => {
						self.send_audio.store(audio, atomic::Ordering::SeqCst);
					},
					message @ Message::AudioChunk {
						..
					} => {
						println!("Received unexpected message from server: {:?}", message);
						return;
					},
					message =>
						match self.input_endpoint.send_message(message) {
							Ok(_) => (),
							Err(e) => self.signal_error(format!("Failed to send message to input: {}", e)),
						},
				},
			None => {
				println!("Received invalid message from server.");
				return;
			},
		};
	}

	fn send_message(&self, message: Message) -> bool {
		println!("Sending {:?}", message);
		// TODO: disconnect on error?
		self.socket.send(message.encode()).is_ok()
	}

	fn signal_error(&self, e: String) {
		*self.error.lock() = Some(e);
		self.error_cond.notify_one();
	}

	pub fn wait_for_exit(&self) -> Result<(), String> {
		let mut error_gu = self.error.lock();

		while error_gu.is_none() {
			match self.audio_snd_h.as_ref() {
				Some(thrd_h) =>
					if thrd_h.is_finished() {
						*error_gu = Some(String::from("audio receiving thread has exited"));
					} else {
						self.error_cond.wait(&mut error_gu);
					},
				None => self.error_cond.wait(&mut error_gu),
			}
		}

		self.input_endpoint.exit();

		if let Some(audio_source) = self.audio_source.as_ref() {
			audio_source.exit();
		}

		let ret = Err(error_gu.take().unwrap());
		*error_gu = Some(format!("error has already been obtained"));
		ret
	}
}
