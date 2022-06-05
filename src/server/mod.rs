pub mod backend;

use self::backend::{new_audio_endpoint, new_input_source, AudioEndpoint, InputSource};
use crate::host_keys::HostKeys;
use crate::message::{Message, MessageTy};
use crate::socket::{HostID, OnConnectFn, OnDisconnectFn, OnReceiveFn, SecureSocket};
use crate::worm::Worm;
use parking_lot::{Condvar, Mutex};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub struct Server {
	socket: Arc<SecureSocket>,
	input_source: Box<dyn InputSource + Send + Sync>,
	audio_endpoint: Option<Box<dyn AudioEndpoint + Send + Sync>>,
	client_id: Worm<HostID>,
	error: Mutex<Option<String>>,
	error_cond: Condvar,
}

impl Server {
	pub fn new(listen_addr: SocketAddr, audio_enable: bool) -> Result<Arc<Worm<Self>>, String> {
		let server: Arc<Worm<Server>> = Arc::new(Worm::new());
		let host_keys = HostKeys::load()?;
		let input_source = new_input_source(Arc::downgrade(&server))
			.map_err(|e| format!("Failed to initialize input source: {}", e))?;

		let audio_endpoint = match audio_enable {
			true => Some(new_audio_endpoint().map_err(|e| format!("Failed to initialize audio endpoint: {}", e))?),
			false => None,
		};

		let server_wk = Arc::downgrade(&server);
		let on_receive: OnReceiveFn = Box::new(move |_, host_id, data| {
			match server_wk.upgrade() {
				Some(server_worm) =>
					match server_worm.blocking_read_timeout(Duration::from_millis(500)) {
						Ok(server) => server.on_receive(host_id, data),
						Err(_) => return,
					},
				None => return,
			}
		});

		let server_wk = Arc::downgrade(&server);
		let on_connect: OnConnectFn = Box::new(move |_, host_id| {
			match server_wk.upgrade() {
				Some(server_worm) =>
					match server_worm.blocking_read_timeout(Duration::from_millis(500)) {
						Ok(server) => server.on_connect(host_id),
						Err(_) => return,
					},
				None => return,
			}
		});

		let server_wk = Arc::downgrade(&server);
		let on_disconnect: OnDisconnectFn = Box::new(move |_, host_id| {
			match server_wk.upgrade() {
				Some(server_worm) =>
					match server_worm.blocking_read_timeout(Duration::from_millis(500)) {
						Ok(server) => server.on_disconnect(host_id),
						Err(_) => return,
					},
				None => return,
			}
		});

		let socket = SecureSocket::listen(host_keys, listen_addr, on_receive, on_connect, on_disconnect)
			.map_err(|e| format!("Failed to create socket: {:?}", e))?;

		server.write(Server {
			socket,
			input_source,
			audio_endpoint,
			client_id: Worm::new(),
			error: Mutex::new(None),
			error_cond: Condvar::new(),
		});

		Ok(server)
	}

	fn on_connect(&self, client_id: HostID) {
		if let Err(e) = self.client_id.try_write(client_id) {
			if e != *self.client_id.read() {
				self.signal_error(String::from("Connection attempted from another client."));
			}
		}
	}

	fn on_disconnect(&self, _: HostID) {}

	fn on_receive(&self, client_id: HostID, data: Vec<u8>) {
		if *self.client_id.read() != client_id {
			println!("A different client tried to send a message!");
			return;
		}

		let message = match Message::decode(data) {
			Some(some) => some,
			None => {
				println!("[Server]: Received invalid message.");
				return;
			},
		};

		match message.ty() {
			MessageTy::ClientFeatures => {
				self.send_message(Message::ServerFeatures {
					audio: self.audio_endpoint.as_ref().map(|endpoint| endpoint.stream_info()),
				});
			},
			MessageTy::AudioChunk =>
				match self.audio_endpoint.as_ref() {
					Some(some) =>
						match some.send_message(message) {
							Ok(_) => (),
							Err(e) => self.signal_error(format!("Failed to send audio chunk to endpoint: {}", e)),
						},
					None => println!("[Server]: Received audio chunk from client, but audio is not enabled!"),
				},
			_ => println!("[Server]: Received unexpected message from client: {:?}", message),
		}
	}

	fn send_message(&self, message: Message) -> bool {
		match self.client_id.try_read() {
			Ok(client_id) =>
				match self.socket.send_to(message.encode(), client_id.clone()) {
					Ok(_) => true,
					Err(_) => false,
				},
			Err(_) => false,
		}
	}

	fn signal_error(&self, e: String) {
		*self.error.lock() = Some(e);
		self.error_cond.notify_one();
	}

	pub fn wait_for_exit(&self) -> Result<(), String> {
		let mut error_gu = self.error.lock();

		while error_gu.is_none() {
			if let Err(e) = self.input_source.check_status() {
				*error_gu = Some(format!("input {}", e));
				break;
			}

			self.error_cond.wait_for(&mut error_gu, Duration::from_secs(1));
		}

		let ret = Err(error_gu.take().unwrap());
		*error_gu = Some(format!("error has already been obtained"));
		ret
	}
}
