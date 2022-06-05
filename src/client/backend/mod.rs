#[cfg(target_family = "unix")]
pub mod unix;
#[cfg(target_family = "unix")]
use self::unix::audio::PulseAudioSource;
#[cfg(target_family = "unix")]
use self::unix::input::UInputEndpoint;

use crate::client::Client;
use crate::message::Message;
use crate::worm::Worm;
use std::sync::Weak;

pub trait InputEndpoint {
	fn send_message(&self, message: Message) -> Result<(), String>;
}

pub trait AudioSource {
	fn set_stream_info(&self, stream_info: Option<(u8, u32)>) -> Result<(), String>;
}

pub fn new_input_endpoint() -> Result<Box<dyn InputEndpoint + Send + Sync>, String> {
	#[cfg(target_family = "unix")]
	{
		UInputEndpoint::new()
	}
	#[cfg(not(target_family = "unix"))]
	{
		Err(String::from("Platform not supported."))
	}
}

pub fn new_audio_source(_client_wk: Weak<Worm<Client>>) -> Result<Box<dyn AudioSource + Send + Sync>, String> {
	#[cfg(target_family = "unix")]
	{
		PulseAudioSource::new(_client_wk)
	}
	#[cfg(not(target_family = "unix"))]
	{
		Err(String::from("Platform not supported."))
	}
}
