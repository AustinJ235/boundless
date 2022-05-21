use crate::client::backend::AudioSource;
use crate::message::Message;
use crate::AudioStreamInfo;
use atomicring::AtomicRingQueue;
use libpulse_binding::sample::{Format, Spec};
use libpulse_binding::stream::Direction;
use libpulse_simple_binding::Simple;
use parking_lot::{Condvar, Mutex};
use std::sync::atomic::{self, AtomicBool};
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

pub struct PulseAudioSource {
	exit: Arc<AtomicBool>,
	queue: Arc<AtomicRingQueue<Message>>,
	thrd_h: JoinHandle<()>,
}

impl PulseAudioSource {
	pub fn new() -> Result<Box<dyn AudioSource + Send + Sync>, String> {
		let ready_result: Arc<Mutex<Option<Result<(), String>>>> = Arc::new(Mutex::new(None));
		let ready_cond = Arc::new(Condvar::new());
		let thrd_ready_result = ready_result.clone();
		let thrd_ready_cond = ready_cond.clone();
		let exit = Arc::new(AtomicBool::new(false));
		let thrd_exit = exit.clone();
		let queue = Arc::new(AtomicRingQueue::with_capacity(100)); // TODO: what is a good size?
		let thrd_queue = queue.clone();

		let thrd_h = thread::spawn(move || {
			let spec = Spec {
				format: Format::F32le,
				rate: 88200,
				channels: 2,
			};

			let stream_info = AudioStreamInfo {
				channels: spec.channels,
				sample_rate: spec.rate as _,
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
					*thrd_ready_result.lock() = Some(Ok(()));
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

			while let Ok(_) = stream.read(&mut *buffer) {
				if thrd_exit.load(atomic::Ordering::SeqCst) {
					break;
				}

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

				thrd_queue.push_overwrite(Message::AudioChunk {
					sample_rate: stream_info.sample_rate,
					channels: stream_info.channels,
					data: mapped.split_off(0),
				});
			}
		});

		let mut ready_result_lk = ready_result.lock();

		while ready_result_lk.is_none() {
			ready_cond.wait(&mut ready_result_lk);
		}

		ready_result_lk.take().unwrap()?;

		Ok(Box::new(PulseAudioSource {
			exit,
			queue,
			thrd_h,
		}))
	}
}

impl AudioSource for PulseAudioSource {
	fn next_message(&self, timeout: Option<Duration>) -> Result<Option<Message>, String> {
		if let Some(message) = self.queue.try_pop() {
			return Ok(Some(message));
		}

		if self.thrd_h.is_finished() {
			return Err(String::from("thread has panicked"));
		}

		match timeout {
			Some(timeout) => Ok(self.queue.pop_for(timeout)),
			None => Ok(Some(self.queue.pop())),
		}
	}

	fn exit(&self) {
		self.exit.store(true, atomic::Ordering::SeqCst);
	}
}
