#[cfg(target_os = "windows")]
#[macro_use]
extern crate lazy_static;

pub mod client;
pub mod host_keys;
pub mod message;
pub mod server;
pub mod socket;
pub mod worm;

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
	println!("  --enable-audio");
	println!("    Enables audio support. Both client and server need this flag.");
}

fn main() {
	let mut mode: u8 = 0;
	let mut args = std::env::args();
	args.next().unwrap();
	let mut socket_addr: Option<SocketAddr> = None;
	let mut enable_audio = false;

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
			"--enable-audio" => {
				enable_audio = true;
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
			match client::Client::new(socket_addr.unwrap(), enable_audio) {
				Ok(client) =>
					match client.wait_for_exit() {
						Ok(_) => (),
						Err(e) => println!("Client has exited: {}", e),
					},
				Err(e) => println!("Failed to start client: {}", e),
			},
		2 =>
			match server::Server::new(socket_addr.unwrap(), enable_audio) {
				Ok(server) =>
					match server.wait_for_exit() {
						Ok(_) => (),
						Err(e) => println!("Server has exited: {}", e),
					},
				Err(e) => println!("Failed to start server: {}", e),
			},
		_ => unreachable!(),
	}
}

#[derive(Debug, Clone)]
pub struct AudioStreamInfo {
	pub channels: u8,
	pub sample_rate: u16,
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
