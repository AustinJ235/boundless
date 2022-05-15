use crate::server::AudioPlayback;
use crate::AudioStreamInfo;
use atomicring::AtomicRingQueue;
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

pub struct WASAPIPlayback {
	audio_chunks: Arc<AtomicRingQueue<Vec<f32>>>,
	thrd_handle: JoinHandle<Result<(), String>>,
	stream_info: AudioStreamInfo,
}

impl WASAPIPlayback {
	pub fn new() -> Result<Box<dyn AudioPlayback + Send>, String> {
		let audio_chunks = Arc::new(AtomicRingQueue::with_capacity(100));
		let thrd_audio_chunks = audio_chunks.clone();
		let init_res: Arc<Mutex<Option<Result<AudioStreamInfo, String>>>> = Arc::new(Mutex::new(None));
		let init_cond: Arc<Condvar> = Arc::new(Condvar::new());
		let thrd_init_res = init_res.clone();
		let thrd_init_cond = init_cond.clone();

		let thrd_handle: JoinHandle<Result<(), String>> = thread::spawn(move || unsafe {
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
				return Ok(());
			}

			let devices: IMMDeviceEnumerator = match CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL) {
				Ok(ok) => ok,
				Err(e) => {
					*thrd_init_res.lock() = Some(Err(format!("CoCreateInstance(): {:?}", e)));
					thrd_init_cond.notify_one();
					return Ok(());
				},
			};

			let default_device: IMMDevice = match devices.GetDefaultAudioEndpoint(eRender, eConsole) {
				Ok(ok) => ok,
				Err(e) => {
					*thrd_init_res.lock() =
						Some(Err(format!("IMMDeviceEnumerator::GetDefaultAudioEndpoint(): {:?}", e)));
					thrd_init_cond.notify_one();
					return Ok(());
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
				return Ok(());
			}

			let audio_client = mbu_audio_client.assume_init();
			let p_mix_format = match audio_client.GetMixFormat() {
				Ok(ok) => ok,
				Err(e) => {
					*thrd_init_res.lock() = Some(Err(format!("IAudioClient::GetMixFormat(): {:?}", e)));
					thrd_init_cond.notify_one();
					return Ok(());
				},
			};

			let WAVEFORMATEX {
				nChannels,
				nSamplesPerSec,
				nBlockAlign,
				// wFormatTag,
				// nAvgBytesPerSec,
				// wBitsPerSample,
				// cbSize,
				..
			} = ptr::read_unaligned(p_mix_format);

			if let Err(e) =
				audio_client.Initialize(AUDCLNT_SHAREMODE_SHARED, 0, 300000, 0, p_mix_format, ptr::null())
			{
				*thrd_init_res.lock() = Some(Err(format!("IAudioClient::Initialize(): {:?}", e)));
				thrd_init_cond.notify_one();
				return Ok(());
			}

			let ac_buffer_size = match audio_client.GetBufferSize() {
				Ok(ok) => ok,
				Err(e) => {
					*thrd_init_res.lock() = Some(Err(format!("IAudioClient::GetBufferSize(): {:?}", e)));
					thrd_init_cond.notify_one();
					return Ok(());
				},
			};

			let mut mbu_render_client: MaybeUninit<IAudioRenderClient> = MaybeUninit::zeroed();

			if let Err(e) =
				audio_client.GetService(&IAudioRenderClient::IID, mbu_render_client.as_mut_ptr() as *mut _)
			{
				*thrd_init_res.lock() = Some(Err(format!("IAudioClient::GetService(): {:?}", e)));
				thrd_init_cond.notify_one();
				return Ok(());
			}

			*thrd_init_res.lock() = Some(Ok(AudioStreamInfo {
				channels: nChannels as _,
				sample_rate: nSamplesPerSec as _,
			}));

			thrd_init_cond.notify_one();
			let render_client = mbu_render_client.assume_init();
			let mut has_started = false;

			let mut pending_samples: VecDeque<f32> =
				VecDeque::with_capacity(ac_buffer_size as usize * nChannels as usize);
			let zero_threshold = ac_buffer_size / 4;
			let block_duration = Duration::from_micros(
				(((ac_buffer_size / 4) as f64 / nSamplesPerSec as f64) * 1000000.0).trunc() as u64,
			);

			loop {
				let padding = audio_client
					.GetCurrentPadding()
					.map_err(|e| format!("IAudioClient::GetCurrentPadding(): {:?}", e))?;
				let available_size = ac_buffer_size - padding;

				let buffer_samples_available = available_size as usize * nChannels as usize;
				let samples_required_before_block = if padding < zero_threshold {
					(zero_threshold - padding) as usize
				} else {
					0
				};

				while pending_samples.len() < buffer_samples_available {
					match thrd_audio_chunks.try_pop() {
						Some(chunk) =>
							for sample in chunk {
								pending_samples.push_back(sample);
							},
						None => break,
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
					let p_buffer = render_client
						.GetBuffer(frames_to_write)
						.map_err(|e| format!("IAudioRenderClient::GetBuffer(): {:?}", e))?;
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

					render_client
						.ReleaseBuffer(frames_to_write, 0)
						.map_err(|e| format!("IAudioRenderClient::ReleaseBuffer(): {:?}", e))?;

					if !has_started {
						audio_client.Start().map_err(|e| format!("IAudioClient::Start(): {:?}", e))?;
						has_started = true;
					}
				}

				if let Some(chunk) = thrd_audio_chunks.pop_for(block_duration.clone()) {
					for sample in chunk {
						pending_samples.push_back(sample);
					}
				}
			}
		});

		let mut init_res_guard = init_res.lock();

		while init_res_guard.is_none() {
			init_cond.wait(&mut init_res_guard);
		}

		let stream_info = init_res_guard.take().unwrap()?;

		Ok(Box::new(Self {
			audio_chunks,
			stream_info,
			thrd_handle,
		}))
	}
}

impl AudioPlayback for WASAPIPlayback {
	fn push_chunk(&self, chunk: Vec<f32>) -> Result<bool, ()> {
		match self.thrd_handle.is_finished() {
			true => Err(()),
			false =>
				match self.audio_chunks.try_push(chunk) {
					Ok(_) => Ok(false),
					Err(chunk) => {
						self.audio_chunks.push_overwrite(chunk);
						Ok(true)
					},
				},
		}
	}

	fn stream_info(&self) -> Result<AudioStreamInfo, ()> {
		match self.thrd_handle.is_finished() {
			true => Err(()),
			false => Ok(self.stream_info.clone()),
		}
	}

	fn exit(self) -> Result<(), String> {
		match self.thrd_handle.join() {
			Ok(ok) => ok,
			Err(_) => Err(String::from("thread panicked.")),
		}
	}
}
