#[cfg(target_os = "windows")]
#[macro_use]
extern crate lazy_static;

pub mod client;
pub mod host_keys;
pub mod platform;
pub mod secure_socket;
pub mod server;

use crate::host_keys::HostKeys;
use std::io::Write;
use std::net::SocketAddr;
use std::str::FromStr;
use strum::{EnumIter, FromRepr};

fn display_usage() {
	println!("Usage:");
	println!("  --client SOCKET_ADDR [--enable-audio]");
	println!("    Start in client mode connecting to provided addr.");
	println!("    --enable-audio to capture audio");
	println!("  --server SOCKET_ADDR [--enable-audio]");
	println!("    Start in server mode listening on the provided addr.");
	println!("    --enable-audio to listen to audio");
	println!("  --generate-keys");
	println!("    Generate keys to be used for host authentication.");
	println!("  --public-key");
	println!("    Print public key of this system.");
	println!("  --trust PUBLIC_KEY");
	println!("    Trust a public key of another host.");
	println!("  --distrust PUBLIC_KEY");
	println!("    Distrust a public key of another host.");
	println!("  --trusted");
	println!("    List all public keys trusted on this system.");
}

fn main() {
	let mut mode: u8 = 0;
	let mut args = std::env::args();
	args.next().unwrap();
	let mut socket_addr: Option<SocketAddr> = None;

	loop {
		let arg = match args.next() {
			Some(some) => some,
			None => break,
		};

		match arg.as_str() {
			"--help" => {
				display_usage();
				return;
			},
			"--client" => {
				mode = 1;
				socket_addr = match args.next() {
					Some(some) =>
						match SocketAddr::from_str(some.as_str()) {
							Ok(ok) => Some(ok),
							Err(e) => {
								println!("Invalid Address: {}", e);
								println!("Usage: --client SOCKET_ADDR [--enable-audio]");
								return;
							},
						},
					None => {
						println!("Usage: --client SOCKET_ADDR [--enable-audio]");
						return;
					},
				};
			},
			"--server" => {
				mode = 2;
				socket_addr = match args.next() {
					Some(some) =>
						match SocketAddr::from_str(some.as_str()) {
							Ok(ok) => Some(ok),
							Err(e) => {
								println!("Invalid Address: {}", e);
								println!("Usage: SOCKET_ADDR [--enable-audio]");
								return;
							},
						},
					None => {
						println!("Usage: SOCKET_ADDR [--enable-audio]");
						return;
					},
				};
			},
			"--generate-keys" => {
				let data_file_path = match crate::HostKeys::data_file() {
					Ok(ok) => ok,
					Err(e) => {
						println!("[Error]: {}", e);
						return;
					},
				};

				if data_file_path.exists() {
					println!("This will erase existing keys and trusted hosts!");
					print!("  Continue with this action? [y/n]: ");
					std::io::stdout().flush().unwrap();

					let mut line = String::new();

					if !loop {
						std::io::stdin().read_line(&mut line).unwrap();

						match line.trim() {
							"y" | "Y" => break true,
							"n" | "N" => break false,
							_ => {
								print!("  Continue with this action? [y/n]: ");
								std::io::stdout().flush().unwrap();
								line.clear();
							},
						}
					} {
						println!("Aborted.");
						return;
					}
				}

				let host_info = HostKeys::generate();

				if let Err(e) = host_info.save() {
					println!("[Error]: {}", e);
					return;
				}

				println!("Keys have been generated!");
				return;
			},
			"--public-key" => {
				let host_info = match HostKeys::load() {
					Ok(ok) => ok,
					Err(e) => {
						println!("[Error]: {}", e);
						return;
					},
				};

				println!("Public Key: {}", host_info.enc_public_key());
				return;
			},
			"--trust" => {
				let enc_public_key = match args.next() {
					Some(some) => some,
					None => {
						println!("Usage: --trust PUBLIC_KEY");
						return;
					},
				};

				let mut host_info = match HostKeys::load() {
					Ok(ok) => ok,
					Err(e) => {
						println!("[Error]: {}", e);
						return;
					},
				};

				if let Err(e) = host_info.trust(enc_public_key) {
					println!("[Error]: {}", e);
					return;
				}

				if let Err(e) = host_info.save() {
					println!("[Error]: {}", e);
					return;
				}

				println!("Host has been added to the trusted list.");
				return;
			},
			"--distrust" => {
				let enc_public_key = match args.next() {
					Some(some) => some,
					None => {
						println!("Usage: --trust PUBLIC_KEY");
						return;
					},
				};

				let mut host_info = match HostKeys::load() {
					Ok(ok) => ok,
					Err(e) => {
						println!("[Error]: {}", e);
						return;
					},
				};

				if let Err(e) = host_info.distrust(enc_public_key) {
					println!("[Error]: {}", e);
					return;
				}

				if let Err(e) = host_info.save() {
					println!("[Error]: {}", e);
					return;
				}

				println!("Host has been removed to the trusted list.");
				return;
			},
			"--trusted" => {
				let host_info = match HostKeys::load() {
					Ok(ok) => ok,
					Err(e) => {
						println!("[Error]: {}", e);
						return;
					},
				};

				println!("Trusted Public Keys:");

				for pk in host_info.trusted() {
					println!("  {}", pk);
				}

				return;
			},
			_ => (),
		}
	}

	if mode == 0 {
		display_usage();
		return;
	}

	match mode {
		1 =>
			if let Err(e) = client::Client::new(socket_addr.unwrap(), true).wait_for_exit() {
				println!("Unexpected Error: {}", e);
			},
		2 =>
			if let Err(e) = server::Server::new(socket_addr.unwrap(), true).wait_for_exit() {
				println!("Unexpected Error: {}", e);
			},
		_ => unreachable!(),
	}
}

#[derive(Debug, Clone)]
pub struct AudioStreamInfo {
	pub channels: u8,
	pub sample_rate: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub enum KBMSEvent {
	MSPress(MSButton),
	MSRelease(MSButton),
	MSMotion(i32, i32),
	MSScrollV(i16),
	MSScrollH(i16),
	KBPress(KBKey),
	KBRelease(KBKey),
	CaptureStart,
	CaptureEnd,
	ClientInfo {
		audio: bool,
	},
	ServerInfo {
		audio_port: Option<u32>,
	},
	ConnectionCheck,
	ConnectionGood,
	ConnectionBad,
}

impl KBMSEvent {
	pub fn encode(&self, seq: u128) -> Vec<u8> {
		let mut output: Vec<u8> = Vec::new();

		for byte in seq.to_le_bytes() {
			output.push(byte);
		}

		match self {
			KBMSEvent::MSPress(button) => {
				output.push(0);
				output.push(*button as u8);
			},
			KBMSEvent::MSRelease(button) => {
				output.push(1);
				output.push(*button as u8);
			},
			KBMSEvent::MSMotion(x, y) => {
				let x_b = x.to_le_bytes();
				let y_b = y.to_le_bytes();
				output.push(2);

				for byte in x_b.into_iter().chain(y_b.into_iter()) {
					output.push(byte);
				}
			},
			KBMSEvent::MSScrollV(amt) => {
				let a_b = amt.to_le_bytes();
				output.push(3);

				for byte in a_b {
					output.push(byte);
				}
			},
			KBMSEvent::MSScrollH(amt) => {
				let a_b = amt.to_le_bytes();
				output.push(4);

				for byte in a_b {
					output.push(byte);
				}
			},
			KBMSEvent::KBPress(key) => {
				output.push(5);
				output.push(*key as u8);
			},
			KBMSEvent::KBRelease(key) => {
				output.push(6);
				output.push(*key as u8);
			},
			KBMSEvent::CaptureStart => {
				output.push(7);
			},
			KBMSEvent::CaptureEnd => {
				output.push(8);
			},
			KBMSEvent::ClientInfo {
				audio,
			} => {
				output.push(9);
				output.push(*audio as u8);
			},
			KBMSEvent::ServerInfo {
				audio_port,
			} => {
				output.push(10);
				let p_b = audio_port.unwrap_or(0).to_le_bytes();

				for byte in p_b {
					output.push(byte);
				}
			},
			KBMSEvent::ConnectionCheck => {
				output.push(11);
			},
			KBMSEvent::ConnectionGood => {
				output.push(12);
			},
			KBMSEvent::ConnectionBad => {
				output.push(13);
			},
		}

		output
	}

	pub fn decode(bytes: &[u8]) -> Option<(u128, KBMSEvent)> {
		if bytes.len() < 17 {
			return None;
		}

		let seq = u128::from_le_bytes([
			bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
			bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
		]);

		let event = match bytes[16] {
			0 => {
				if bytes.len() < 18 {
					return None;
				}

				match MSButton::from_repr(bytes[17]) {
					Some(some) => KBMSEvent::MSPress(some),
					None => return None,
				}
			},
			1 => {
				if bytes.len() < 18 {
					return None;
				}

				match MSButton::from_repr(bytes[17]) {
					Some(some) => KBMSEvent::MSRelease(some),
					None => return None,
				}
			},
			2 => {
				if bytes.len() < 25 {
					return None;
				}

				let x = i32::from_le_bytes([bytes[17], bytes[18], bytes[19], bytes[20]]);
				let y = i32::from_le_bytes([bytes[21], bytes[22], bytes[23], bytes[24]]);
				KBMSEvent::MSMotion(x, y)
			},
			3 => {
				if bytes.len() < 19 {
					return None;
				}

				let amt = i16::from_le_bytes([bytes[17], bytes[18]]);
				KBMSEvent::MSScrollV(amt)
			},
			4 => {
				if bytes.len() < 19 {
					return None;
				}

				let amt = i16::from_le_bytes([bytes[17], bytes[18]]);
				KBMSEvent::MSScrollH(amt)
			},
			5 => {
				if bytes.len() < 18 {
					return None;
				}

				match KBKey::from_repr(bytes[17]) {
					Some(some) => KBMSEvent::KBPress(some),
					None => return None,
				}
			},
			6 => {
				if bytes.len() < 18 {
					return None;
				}

				match KBKey::from_repr(bytes[17]) {
					Some(some) => KBMSEvent::KBRelease(some),
					None => return None,
				}
			},
			7 => KBMSEvent::CaptureStart,
			8 => KBMSEvent::CaptureEnd,
			9 => {
				if bytes.len() < 18 {
					return None;
				}

				let audio = match bytes[17] {
					0 => false,
					1 => true,
					_ => return None,
				};

				KBMSEvent::ClientInfo {
					audio,
				}
			},
			10 => {
				if bytes.len() < 21 {
					return None;
				}

				let audio_port = match u32::from_le_bytes([bytes[17], bytes[18], bytes[19], bytes[20]]) {
					0 => None,
					p => Some(p),
				};

				KBMSEvent::ServerInfo {
					audio_port,
				}
			},
			11 => KBMSEvent::ConnectionCheck,
			12 => KBMSEvent::ConnectionGood,
			13 => KBMSEvent::ConnectionBad,
			_ => return None,
		};

		Some((seq, event))
	}
}

#[derive(Debug, Clone, Copy, PartialEq, FromRepr, EnumIter)]
#[repr(u8)]
pub enum MSButton {
	Left,
	Middle,
	Right,
}

#[derive(Debug, Clone, Copy, PartialEq, FromRepr, EnumIter)]
#[repr(u8)]
pub enum KBKey {
	Esc,
	Grave,
	One,
	Two,
	Three,
	Four,
	Five,
	Six,
	Seven,
	Eight,
	Nine,
	Zero,
	Minus,
	Equal,
	Backspace,
	Tab,
	Q,
	W,
	E,
	R,
	T,
	Y,
	U,
	I,
	O,
	P,
	LeftBrace,
	RightBrace,
	Backslash,
	CapsLock,
	A,
	S,
	D,
	F,
	G,
	H,
	J,
	K,
	L,
	SemiColon,
	Apostrophe,
	Enter,
	LeftShift,
	Z,
	X,
	C,
	V,
	B,
	N,
	M,
	Comma,
	Dot,
	Slash,
	RightShift,
	LeftControl,
	LeftMeta,
	RightMeta,
	LeftAlt,
	Space,
	RightAlt,
	Fn,
	RightControl,
	Insert,
	Delete,
	PageUp,
	PageDown,
	Sysrq,
	ScrollLock,
	Pause,
	Home,
	End,
	ArrowUp,
	ArrowDown,
	ArrowLeft,
	ArrowRight,
	F1,
	F2,
	F3,
	F4,
	F5,
	F6,
	F7,
	F8,
	F9,
	F10,
	F11,
	F12,
}
