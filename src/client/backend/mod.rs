use crate::message::Message;
use std::time::Duration;

pub trait InputEndpoint {
	fn send_message(&self, message: Message) -> Result<(), String>;
	fn exit(&self);
}

pub trait AudioSource {
	fn next_message(&self, timeout: Option<Duration>) -> Result<Option<Message>, String>;
	fn exit(&self);
}

pub fn new_input_endpoint() -> Result<Box<dyn InputEndpoint + Send + Sync>, String> {
	todo!()
}

pub fn new_audio_source() -> Result<Box<dyn AudioSource + Send + Sync>, String> {
	todo!()
}
