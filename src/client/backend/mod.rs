#[cfg(target_family = "unix")]
pub mod unix;
#[cfg(target_family = "unix")]
use self::unix::audio::PulseAudioSource;
#[cfg(target_family = "unix")]
use self::unix::input::UInputEndpoint;

use crate::message::Message;
use std::time::Duration;

pub trait InputEndpoint {
	fn send_message(&self, message: Message) -> Result<(), String>;
	fn exit(&self);
}

pub trait AudioSource {
	fn next_message(&self, timeout: Option<Duration>) -> Result<Option<Message>, String>;
	fn set_stream_info(&self, stream_info: Option<(u8, u16)>);
	fn exit(&self);
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

pub fn new_audio_source() -> Result<Box<dyn AudioSource + Send + Sync>, String> {
	#[cfg(target_family = "unix")]
	{
		PulseAudioSource::new()
	}
	#[cfg(not(target_family = "unix"))]
	{
		Err(String::from("Platform not supported."))
	}
}
