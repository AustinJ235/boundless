use crate::server::AudioPlayback;
use crate::AudioStreamInfo;
use atomicring::AtomicRingQueue;
use std::f32::consts::PI;
use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::{ptr, slice};
use windows::core::Interface;
use windows::Win32::Media::Audio::{
	eConsole, eRender, IAudioClient, IAudioRenderClient, IMMDevice, IMMDeviceEnumerator,
	MMDeviceEnumerator, AUDCLNT_SHAREMODE_SHARED, WAVEFORMATEX,
};
use windows::Win32::System::Com::{
	CoCreateInstance, CoInitializeEx, CLSCTX_ALL, COINIT_APARTMENTTHREADED,
};

pub struct WASAPIPlayback {
	event_queue: Arc<AtomicRingQueue<Vec<f32>>>,
}

enum Event {
	Config(AudioStreamInfo),
	Data(Vec<f32>),
}

impl WASAPIPlayback {
	pub fn new() -> Box<dyn AudioPlayback> {
		let event_queue = Arc::new(AtomicRingQueue::with_capacity(100));
		let thd_event_queue = event_queue.clone();

		let _handle: JoinHandle<Result<(), String>> = thread::spawn(move || unsafe {
			CoInitializeEx(ptr::null(), COINIT_APARTMENTTHREADED)
				.map_err(|e| format!("CoInitializeEx(): {:?}", e))?;
			let devices: IMMDeviceEnumerator =
				CoCreateInstance(&MMDeviceEnumerator, None, CLSCTX_ALL)
					.map_err(|e| format!("CoCreateInstance(): {:?}", e))?;
			let default_device: IMMDevice =
				devices.GetDefaultAudioEndpoint(eRender, eConsole).map_err(|e| {
					format!("IMMDeviceEnumerator::GetDefaultAudioEndpoint(): {:?}", e)
				})?;
			let mut mbu_audio_client: MaybeUninit<IAudioClient> = MaybeUninit::zeroed();

			default_device
				.Activate(
					&IAudioClient::IID,
					CLSCTX_ALL,
					ptr::null(),
					mbu_audio_client.as_mut_ptr() as *mut _,
				)
				.map_err(|e| format!("IMMDevice::Activate(): {:?}", e))?;

			let audio_client = mbu_audio_client.assume_init();
			let p_mix_format = audio_client
				.GetMixFormat()
				.map_err(|e| format!("IAudioClient::GetMixFormat(): {:?}", e))?;

			let WAVEFORMATEX {
				wFormatTag,
				nChannels,
				nSamplesPerSec,
				nAvgBytesPerSec,
				nBlockAlign,
				wBitsPerSample,
				cbSize,
			} = ptr::read_unaligned(p_mix_format);

			audio_client
				.Initialize(
					AUDCLNT_SHAREMODE_SHARED,
					0,
					300000, // 30ms TODO: Lessen when not using sleep
					0,
					p_mix_format,
					ptr::null(),
				)
				.map_err(|e| format!("IAudioClient::Initialize(): {:?}", e))?;

			let ac_buffer_size = audio_client
				.GetBufferSize()
				.map_err(|e| format!("IAudioClient::GetBufferSize(): {:?}", e))?;
			let mut mbu_render_client: MaybeUninit<IAudioRenderClient> = MaybeUninit::zeroed();

			audio_client
				.GetService(&IAudioRenderClient::IID, mbu_render_client.as_mut_ptr() as *mut _)
				.map_err(|e| format!("IAudioClient::GetService(): {:?}", e))?;

			let render_client = mbu_render_client.assume_init();
			let mut has_started = false;
			let mut time = 0.0_f32;
			let frame_time = 1.0 / nSamplesPerSec as f32;

			loop {
				let padding = audio_client
					.GetCurrentPadding()
					.map_err(|e| format!("IAudioClient::GetCurrentPadding(): {:?}", e))?;
				let available_size = ac_buffer_size - padding;
				let p_buffer = render_client
					.GetBuffer(available_size)
					.map_err(|e| format!("IAudioRenderClient::GetBuffer(): {:?}", e))?;
				let buffer_bytes = slice::from_raw_parts_mut(
					p_buffer,
					available_size as usize * nBlockAlign as usize,
				);

				for frame_bytes in buffer_bytes.chunks_exact_mut(nBlockAlign as usize) {
					let sample = (2.0 * 440.0 * PI * time).sin();
					time += frame_time;

					for sample_bytes in
						frame_bytes.chunks_exact_mut((nBlockAlign / nChannels) as usize)
					{
						for (src, dst) in sample.to_le_bytes().into_iter().zip(sample_bytes) {
							*dst = src;
						}
					}
				}

				render_client
					.ReleaseBuffer(available_size, 0)
					.map_err(|e| format!("IAudioRenderClient::ReleaseBuffer(): {:?}", e))?;

				if !has_started {
					audio_client
						.Start()
						.map_err(|e| format!("IAudioClient::Start(): {:?}", e))?;
					has_started = true;
				}

				thread::sleep(std::time::Duration::from_millis(5));
			}

			Ok(())
		});

		Box::new(Self {
			event_queue,
		})
	}
}

impl AudioPlayback for WASAPIPlayback {
	fn set_stream_info(&self, info: AudioStreamInfo) {
		todo!()
	}

	fn push_chunk(&self, chunk: Vec<f32>) {
		todo!()
	}
}
