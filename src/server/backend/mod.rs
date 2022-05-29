#[cfg(target_os = "windows")]
pub mod win32;
#[cfg(target_os = "windows")]
use self::win32::audio::WASAPIPlayback;
#[cfg(target_os = "windows")]
use self::win32::input::Win32Input;
use crate::message::Message;
use std::time::Duration;

pub trait InputSource {
	fn next_message(&self, timeout: Option<Duration>) -> Result<Option<Message>, String>;
	fn exit(&self);
}

pub trait AudioEndpoint {
	fn send_message(&self, message: Message) -> Result<(), String>;
	fn stream_info(&self) -> (u8, u16);
	fn exit(&self);
}

pub fn new_input_source() -> Result<Box<dyn InputSource + Send + Sync>, String> {
	#[cfg(target_os = "windows")]
	{
		Win32Input::new()
	}
	#[cfg(not(target_os = "windows"))]
	{
		Err(String::from("Platform not supported."))
	}
}

pub fn new_audio_endpoint() -> Result<Box<dyn AudioEndpoint + Send + Sync>, String> {
	#[cfg(target_os = "windows")]
	{
		WASAPIPlayback::new()
	}
	#[cfg(not(target_os = "windows"))]
	{
		Err(String::from("Platform not supported."))
	}
}
