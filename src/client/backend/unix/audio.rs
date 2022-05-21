use crate::client::AudioCapture;
use crate::AudioStreamInfo;
use libpulse_binding::sample::{Format, Spec};
use libpulse_binding::stream::Direction;
use libpulse_simple_binding::Simple;
use parking_lot::{Condvar, Mutex};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::thread;

pub struct PulseAudioCapture {
	stream_info: AudioStreamInfo,
	send_addr: Arc<Mutex<Option<SocketAddr>>>,
}

impl PulseAudioCapture {
	pub fn new() -> Result<Box<dyn AudioCapture>, String> {
		let ready_result: Arc<Mutex<Option<Result<AudioStreamInfo, String>>>> = Arc::new(Mutex::new(None));
		let ready_cond = Arc::new(Condvar::new());
		let thrd_ready_result = ready_result.clone();
		let thrd_ready_cond = ready_cond.clone();
		let send_addr = Arc::new(Mutex::new(None));
		let thrd_send_addr = send_addr.clone();

		thread::spawn(move || {
			let spec = Spec {
				format: Format::F32le,
				rate: 88200,
				channels: 2,
			};

			let stream_info = AudioStreamInfo {
				channels: spec.channels,
				sample_rate: spec.rate as _,
			};

			let socket = match UdpSocket::bind("0.0.0.0:0") {
				Ok(ok) => ok,
				Err(e) => {
					*thrd_ready_result.lock() = Some(Err(format!("Failed to bind audio socket: {}", e)));
					thrd_ready_cond.notify_one();
					return;
				},
			};

			let stream = match Simple::new(
				None,
				"Boundless",
				Direction::Record,
				Some("boundless.monitor"),
				"Monitor",
				&spec,
				None,
				None,
			) {
				Ok(stream) => {
					*thrd_ready_result.lock() = Some(Ok(stream_info));
					thrd_ready_cond.notify_one();
					stream
				},
				Err(e) => {
					*thrd_ready_result.lock() = Some(Err(format!("Failed to create stream: {}", e)));
					thrd_ready_cond.notify_one();
					return;
				},
			};

			let buffer_size = (spec.rate as f32 / 1000.0 * 10.0 * spec.channels as f32).trunc() as usize;
			let mut buffer = vec![0_u8; buffer_size * spec.format.size()];
			let mut mapped: Vec<f32> = Vec::with_capacity(buffer_size);
			let mut socket_buf: Vec<u8> = Vec::with_capacity(buffer_size * 4);

			while let Ok(_) = stream.read(&mut *buffer) {
				match spec.format {
					Format::S16le =>
						for chunk in buffer.chunks_exact(2) {
							let si16 = i16::from_le_bytes([chunk[0], chunk[1]]);
							mapped.push(si16 as f32 / i16::max_value() as f32);
						},
					Format::S16be =>
						for chunk in buffer.chunks_exact(2) {
							let si16 = i16::from_be_bytes([chunk[0], chunk[1]]);
							mapped.push(si16 as f32 / i16::max_value() as f32);
						},
					Format::F32le =>
						for chunk in buffer.chunks_exact(4) {
							mapped.push(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
						},
					Format::F32be =>
						for chunk in buffer.chunks_exact(4) {
							mapped.push(f32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
						},
					Format::S32le =>
						for chunk in buffer.chunks_exact(4) {
							let si32 = i32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
							mapped.push(si32 as f32 / i32::max_value() as f32);
						},
					Format::S32be =>
						for chunk in buffer.chunks_exact(4) {
							let si32 = i32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
							mapped.push(si32 as f32 / i32::max_value() as f32);
						},
					_ => unimplemented!(),
				}

				if let Some(send_to) = thrd_send_addr.lock().clone() {
					for sample in mapped.iter() {
						for byte in sample.to_le_bytes() {
							socket_buf.push(byte);
						}
					}

					if let Err(e) = socket.send_to(&*socket_buf, send_to) {
						println!("[Audio]: Failed to send audio packet: {}", e);
					}

					socket_buf.clear();
				}

				mapped.clear();
			}

			unreachable!()
		});

		let mut ready_result_lk = ready_result.lock();

		while ready_result_lk.is_none() {
			ready_cond.wait(&mut ready_result_lk);
		}

		let stream_info = ready_result_lk.take().unwrap()?;

		Ok(Box::new(PulseAudioCapture {
			stream_info,
			send_addr,
		}))
	}
}

impl AudioCapture for PulseAudioCapture {
	fn stream_info(&self) -> AudioStreamInfo {
		self.stream_info.clone()
	}

	fn set_socket_addr(&self, addr: Option<SocketAddr>) {
		*self.send_addr.lock() = addr;
	}
}
