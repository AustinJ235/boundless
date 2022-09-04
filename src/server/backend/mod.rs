#[cfg(target_os = "windows")]
pub mod win32;
use std::sync::Weak;

#[cfg(target_os = "windows")]
use self::win32::audio::WASAPIPlayback;
#[cfg(target_os = "windows")]
use self::win32::input::Win32Input;
use crate::message::Message;
use crate::server::Server;
use crate::worm::Worm;

pub trait InputSource {
    fn check_status(&self) -> Result<(), String>;
}

pub trait AudioEndpoint {
    fn send_message(&self, message: Message) -> Result<(), String>;
    fn stream_info(&self) -> (u8, u32);
}

pub fn new_input_source(
    _server_wk: Weak<Worm<Server>>,
) -> Result<Box<dyn InputSource + Send + Sync>, String> {
    #[cfg(target_os = "windows")]
    {
        Win32Input::new(_server_wk)
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
