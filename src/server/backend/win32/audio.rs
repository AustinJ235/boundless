use crate::message::Message;
use crate::server::backend::AudioEndpoint;
use flume::{RecvTimeoutError, Sender, TryRecvError, TrySendError};
use parking_lot::{Condvar, Mutex};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use std::{ptr, slice};
use windows::core::Interface;
use windows::Win32::Media::Audio::{
	eConsole, eRender, IAudioClient, IAudioRenderClient, IMMDevice, IMMDeviceEnumerator, MMDeviceEnumerator,
	AUDCLNT_SHAREMODE_SHARED, WAVEFORMATEX,
};
use windows::Win32::System::Com::{CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_APARTMENTTHREADED};

thread_local! {
	static COM_INIT: RefCell<bool> = RefCell::new(false);
}

#[allow(dead_code)]
pub struct WASAPIPlayback {
	send_queue: Sender<Vec<f32>>,
	thrd_h: JoinHandle<()>,
	stream_info: (u8, u32),
}

impl WASAPIPlayback {
	pub fn new() -> Result<Box<dyn AudioEndpoint + Send + Sync>, String> {
		let (send_queue, recv_queue): (Sender<Vec<f32>>, _) = flume::bounded(2);
		let init_res: Arc<Mutex<Option<Result<(u8, u32), String>>>> = Arc::new(Mutex::new(None));
		let init_cond: Arc<Condvar> = Arc::new(Condvar::new());
		let thrd_init_res = init_res.clone();
		let thrd_init_cond = init_cond.clone();

		let thrd_h = thread::spawn(move || unsafe {
			if let Err(e) = COM_INIT.with(|com_init_ref| -> Result<(), String> {
				let mut com_init = com_init_ref.borrow_mut();

				if !*com_init {
					match CoInitializeEx(ptr::null(), COINIT_APARTMENTTHREADED) {
						Ok(_) => {
							*com_init = true;
							Ok(())
						},
						Err(e) => Err(format!("{:?}", e)),
					}
				} else {
					Ok(())
				}
			}) {
				*thrd_init_res.lock() = Some(Err(format!("CoInitializeEx(): {}", e)));
				thrd_init_cond.notify_one();
				return;
			}

			let devices: IMMDeviceEnumerator = match CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL) {
				Ok(ok) => ok,
				Err(e) => {
					*thrd_init_res.lock() = Some(Err(format!("CoCreateInstance(): {:?}", e)));
					thrd_init_cond.notify_one();
					return;
				},
			};

			let default_device: IMMDevice = match devices.GetDefaultAudioEndpoint(eRender, eConsole) {
				Ok(ok) => ok,
				Err(e) => {
					*thrd_init_res.lock() =
						Some(Err(format!("IMMDeviceEnumerator::GetDefaultAudioEndpoint(): {:?}", e)));
					thrd_init_cond.notify_one();
					return;
				},
			};

			let mut mbu_audio_client: MaybeUninit<IAudioClient> = MaybeUninit::zeroed();

			if let Err(e) = default_device.Activate(
				&IAudioClient::IID,
				CLSCTX_ALL,
				ptr::null(),
				mbu_audio_client.as_mut_ptr() as *mut _,
			) {
				*thrd_init_res.lock() = Some(Err(format!("IMMDevice::Activate(): {:?}", e)));
				thrd_init_cond.notify_one();
				return;
			}

			let audio_client = mbu_audio_client.assume_init();
			let p_mix_format = match audio_client.GetMixFormat() {
				Ok(ok) => ok,
				Err(e) => {
					*thrd_init_res.lock() = Some(Err(format!("IAudioClient::GetMixFormat(): {:?}", e)));
					thrd_init_cond.notify_one();
					return;
				},
			};

			let WAVEFORMATEX {
				nChannels,
				nSamplesPerSec,
				nBlockAlign,
				..
			} = ptr::read_unaligned(p_mix_format);

			if let Err(e) =
				audio_client.Initialize(AUDCLNT_SHAREMODE_SHARED, 0, 300_000, 0, p_mix_format, ptr::null())
			// 30 ms
			{
				*thrd_init_res.lock() = Some(Err(format!("IAudioClient::Initialize(): {:?}", e)));
				thrd_init_cond.notify_one();
				return;
			}

			let ac_buffer_size = match audio_client.GetBufferSize() {
				Ok(ok) => ok,
				Err(e) => {
					*thrd_init_res.lock() = Some(Err(format!("IAudioClient::GetBufferSize(): {:?}", e)));
					thrd_init_cond.notify_one();
					return;
				},
			};

			let mut mbu_render_client: MaybeUninit<IAudioRenderClient> = MaybeUninit::zeroed();

			if let Err(e) =
				audio_client.GetService(&IAudioRenderClient::IID, mbu_render_client.as_mut_ptr() as *mut _)
			{
				*thrd_init_res.lock() = Some(Err(format!("IAudioClient::GetService(): {:?}", e)));
				thrd_init_cond.notify_one();
				return;
			}

			*thrd_init_res.lock() = Some(Ok((nChannels as _, nSamplesPerSec as _)));
			thrd_init_cond.notify_one();
			let render_client = mbu_render_client.assume_init();
			let mut has_started = false;

			let mut pending_samples: VecDeque<f32> =
				VecDeque::with_capacity(ac_buffer_size as usize * nChannels as usize);
			let block_duration = Duration::from_millis(15);
			// number of frames consumed during block
			let zero_threshold = (nSamplesPerSec as f32 * (15.0 / 1000.0)).ceil() as u32;

			loop {
				let padding = match audio_client.GetCurrentPadding() {
					Ok(ok) => ok,
					Err(e) => {
						println!("[Audio]: IAudioClient::GetCurrentPadding(): {:?}", e);
						return;
					},
				};

				let available_size = ac_buffer_size - padding;
				let buffer_samples_available = available_size as usize * nChannels as usize;

				let samples_required_before_block = if padding < zero_threshold {
					(zero_threshold - padding) as usize
				} else {
					0
				};

				while pending_samples.len() < buffer_samples_available {
					match recv_queue.try_recv() {
						Ok(chunk) => chunk.into_iter().for_each(|s| pending_samples.push_back(s)),
						Err(TryRecvError::Empty) => break,
						Err(TryRecvError::Disconnected) => return,
					}
				}

				let mut zero_samples = 0;

				if pending_samples.len() < samples_required_before_block {
					zero_samples = samples_required_before_block - pending_samples.len();
				}

				let write_samples_count = if pending_samples.len() > buffer_samples_available {
					buffer_samples_available
				} else {
					pending_samples.len() + zero_samples
				};

				if write_samples_count > 0 {
					let mut samples_to_write: Vec<f32> = Vec::with_capacity(write_samples_count);

					while samples_to_write.len() < write_samples_count - zero_samples {
						samples_to_write.push(pending_samples.pop_front().unwrap());
					}

					for _ in 0..zero_samples {
						samples_to_write.push(0.0);
					}

					let frames_to_write = write_samples_count as u32 / nChannels as u32;

					let p_buffer = match render_client.GetBuffer(frames_to_write) {
						Ok(ok) => ok,
						Err(e) => {
							println!("[Audio]: IAudioRenderClient::GetBuffer(): {:?}", e);
							return;
						},
					};

					let buffer_bytes =
						slice::from_raw_parts_mut(p_buffer, frames_to_write as usize * nBlockAlign as usize);

					for (dst_bytes, src) in buffer_bytes
						.chunks_exact_mut((nBlockAlign / nChannels) as usize)
						.zip(samples_to_write.into_iter())
					{
						for (dst_byte, src_byte) in dst_bytes.into_iter().zip(src.to_le_bytes().into_iter()) {
							*dst_byte = src_byte;
						}
					}

					if let Err(e) = render_client.ReleaseBuffer(frames_to_write, 0) {
						println!("[Audio]: IAudioRenderClient::ReleaseBuffer(): {:?}", e);
						return;
					}

					if !has_started {
						if let Err(e) = audio_client.Start() {
							println!("[Audio]: IAudioClient::Start(): {:?}", e);
							return;
						}

						has_started = true;
					}
				}

				match recv_queue.recv_timeout(block_duration.clone()) {
					Ok(chunk) => chunk.into_iter().for_each(|s| pending_samples.push_back(s)),
					Err(RecvTimeoutError::Timeout) => (),
					Err(RecvTimeoutError::Disconnected) => return,
				}
			}
		});

		let mut init_res_guard = init_res.lock();

		while init_res_guard.is_none() {
			init_cond.wait(&mut init_res_guard);
		}

		let stream_info = init_res_guard.take().unwrap()?;

		Ok(Box::new(Self {
			send_queue,
			stream_info,
			thrd_h,
		}))
	}
}

impl AudioEndpoint for WASAPIPlayback {
	fn send_message(&self, message: Message) -> Result<(), String> {
		match message {
			Message::AudioChunk {
				data,
				channels,
				sample_rate,
			} =>
				if self.stream_info.0 != channels {
					println!(
						"[Audio]: Rejected audio chunk, reason: expected {} channels, but recv'd {} channels.",
						self.stream_info.0, channels
					);
					Ok(())
				} else if self.stream_info.1 != sample_rate {
					println!(
						"[Audio]: Rejected audio chunk, reason: expected sample rate of {} Hz, but recv'd {} Hz.",
						self.stream_info.1, sample_rate
					);
					Ok(())
				} else {
					match self.send_queue.try_send(data) {
						Ok(_) => Ok(()),
						Err(TrySendError::Full(_)) => {
							println!("[Audio]: Rejected audio chunk, reason: queue is full.");
							Ok(())
						},
						Err(TrySendError::Disconnected(_)) => Err(String::from("playback thread has exited.")),
					}
				},
			_ => unreachable!(),
		}
	}

	fn stream_info(&self) -> (u8, u32) {
		self.stream_info
	}
}
