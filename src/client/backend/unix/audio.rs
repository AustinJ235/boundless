use crate::client::backend::AudioSource;
use crate::client::Client;
use crate::message::Message;
use crate::worm::Worm;
use flume::{RecvTimeoutError, Sender, TryRecvError};
use libpulse_binding::sample::{Format, Spec};
use libpulse_binding::stream::Direction;
use libpulse_simple_binding::Simple;
use std::sync::Weak;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

#[allow(dead_code)]
pub struct PulseAudioSource {
	thrd_h: JoinHandle<()>,
	info_snd: Sender<Option<(u8, u32)>>,
}

impl PulseAudioSource {
	pub fn new(client_wk: Weak<Worm<Client>>) -> Result<Box<dyn AudioSource + Send + Sync>, String> {
		let (info_snd, info_rcv) = flume::unbounded();

		let thrd_h = thread::spawn(move || {
			let mut stream_info: Option<(u8, u32)> = None;

			'init: loop {
				loop {
					match info_rcv.try_recv() {
						Ok(info_op) => {
							stream_info = info_op;
							break;
						},
						Err(TryRecvError::Empty) => break,
						Err(TryRecvError::Disconnected) => return,
					}
				}

				if stream_info.is_none() {
					match info_rcv.recv_timeout(Duration::from_millis(500)) {
						Ok(info_op) => {
							stream_info = info_op;

							if info_op.is_none() {
								continue;
							}
						},
						Err(RecvTimeoutError::Timeout) => continue,
						Err(RecvTimeoutError::Disconnected) => return,
					}
				}

				let spec = Spec {
					format: Format::F32le,
					rate: stream_info.as_ref().unwrap().1 as _,
					channels: stream_info.as_ref().unwrap().0 as _,
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
					Ok(ok) => ok,
					Err(e) => {
						// TODO: Check if a remap or ressample is needed?
						println!(
							"[Audio]: Failed to initiate stream with ({} Channels @ {} Hz): {}",
							spec.channels, spec.rate, e
						);
						stream_info = None;
						continue;
					},
				};

				let buffer_size = (spec.rate as f32 / 1000.0 * 10.0 * spec.channels as f32).trunc() as usize;
				let mut buffer = vec![0_u8; buffer_size * spec.format.size()];
				let mut mapped: Vec<f32> = Vec::with_capacity(buffer_size);
				println!("[Audio]: Monitoring at {} channels @ {} Hz", spec.channels, spec.rate);

				loop {
					let mut info_updated = false;
					let mut new_info = None;

					loop {
						match info_rcv.try_recv() {
							Ok(info_op) => {
								info_updated = true;
								new_info = info_op;
								break;
							},
							Err(TryRecvError::Empty) => break,
							Err(TryRecvError::Disconnected) => return,
						}
					}

					if info_updated && new_info != stream_info {
						stream_info = new_info;
						continue 'init;
					}

					if let Err(e) = stream.read(&mut *buffer) {
						println!("[Audio]: Failed to read stream: {}", e);
						stream_info = None;
						continue 'init;
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

					// upgrade & try read and exit if either fails, if stream info is recv'd,
					// that means that the client *should* be intialized and in a case where
					// either fails means that the client has been dropped.
					match client_wk.upgrade() {
						Some(worm) =>
							match worm.try_read() {
								Ok(client) => {
									client.send_message(Message::AudioChunk {
										sample_rate: spec.rate as _,
										channels: spec.channels as _,
										data: mapped.split_off(0),
									});
								},
								Err(_) => break,
							},
						None => break,
					}
				}
			}
		});

		Ok(Box::new(PulseAudioSource {
			thrd_h,
			info_snd,
		}))
	}
}

impl AudioSource for PulseAudioSource {
	fn set_stream_info(&self, stream_info: Option<(u8, u32)>) -> Result<(), String> {
		match self.info_snd.send(stream_info) {
			Ok(_) => Ok(()),
			Err(_) => Err(String::from("thread has exited")),
		}
	}
}
