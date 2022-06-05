pub mod backend;

use self::backend::{new_audio_source, new_input_endpoint, AudioSource, InputEndpoint};
use crate::host_keys::HostKeys;
use crate::message::Message;
use crate::socket::{OnConnectFn, OnDisconnectFn, OnReceiveFn, SecureSocket};
use crate::worm::Worm;
use parking_lot::{Condvar, Mutex};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub struct Client {
	socket: Arc<SecureSocket>,
	input_endpoint: Box<dyn InputEndpoint + Send + Sync>,
	audio_source: Option<Box<dyn AudioSource + Send + Sync>>,
	error: Mutex<Option<String>>,
	error_cond: Condvar,
}

impl Client {
	pub fn new(connect_to: SocketAddr, audio_enable: bool) -> Result<Arc<Worm<Self>>, String> {
		let client: Arc<Worm<Client>> = Arc::new(Worm::new());
		let host_keys = HostKeys::load()?;
		let input_endpoint =
			new_input_endpoint().map_err(|e| format!("Failed to initialize input endpoint: {}", e))?;

		let audio_source = match audio_enable {
			true =>
				Some(
					new_audio_source(Arc::downgrade(&client))
						.map_err(|e| format!("Failed to initialize audio source: {}", e))?,
				),
			false => None,
		};

		let client_wk = Arc::downgrade(&client);
		let on_receive: OnReceiveFn = Box::new(move |_, _, data| {
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
		let on_connect: OnConnectFn = Box::new(move |_, _| {
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
		let on_disconnect: OnDisconnectFn = Box::new(move |_, _| {
			match client_wk.upgrade() {
				Some(client_worm) =>
					match client_worm.blocking_read_timeout(Duration::from_millis(500)) {
						Ok(client) => client.on_disconnect(),
						Err(_) => return,
					},
				None => return,
			}
		});

		let socket = SecureSocket::connect(host_keys, connect_to, on_receive, on_connect, on_disconnect)
			.map_err(|e| format!("Failed to create socket: {:?}", e))?;

		client.write(Client {
			socket,
			input_endpoint,
			audio_source,
			error: Mutex::new(None),
			error_cond: Condvar::new(),
		});

		Ok(client)
	}

	fn on_connect(&self) {
		self.send_message(Message::ClientFeatures {
			audio: self.audio_source.is_some(),
		});
	}

	fn on_disconnect(&self) {
		self.audio_source.as_ref().map(|audio_source| audio_source.set_stream_info(None));
	}

	fn on_receive(&self, data: Vec<u8>) {
		match Message::decode(data) {
			Some(message) =>
				match message {
					Message::ServerFeatures {
						audio,
					} =>
						match &self.audio_source {
							Some(audio_source) =>
								match audio {
									Some(stream_info) => {
										if let Err(e) = audio_source.set_stream_info(Some(stream_info)) {
											self.signal_error(format!(
												"[Audio]: Failed to sent stream info: {}",
												e
											));
										}
									},
									None =>
										if let Err(e) = audio_source.set_stream_info(None) {
											self.signal_error(format!(
												"[Audio]: Failed to sent stream info: {}",
												e
											));
										},
								},
							None => (),
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
		self.socket.send(message.encode()).is_ok()
	}

	fn signal_error(&self, e: String) {
		*self.error.lock() = Some(e);
		self.error_cond.notify_one();
	}

	pub fn wait_for_exit(&self) -> Result<(), String> {
		let mut error_gu = self.error.lock();

		while error_gu.is_none() {
			self.error_cond.wait(&mut error_gu);
		}

		let ret = Err(error_gu.take().unwrap());
		*error_gu = Some(format!("error has already been obtained"));
		ret
	}
}
