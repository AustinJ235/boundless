pub mod client;
pub mod platform;
pub mod server;
#[cfg(target_os = "windows")]
pub mod windows;

use strum::FromRepr;

fn main() {
	#[cfg(target_os = "windows")]
	{
		let server = match server::Server::new() {
			Ok(ok) => ok,
			Err(e) => {
				println!("Failed to start server: {}", e);
				return;
			},
		};

		loop {
			while let Some(event) = server.next_event() {
				println!("{:?}", event);
			}

			std::thread::sleep(std::time::Duration::from_millis(15));
		}
	}

	#[cfg(target_family = "unix")]
	{
		if let Err(e) = client::Client::new().wait_for_exit() {
			println!("Unexpected Error: {}", e);
		}
	}
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
}

#[derive(Debug, Clone, PartialEq, FromRepr)]
#[repr(u8)]
pub enum MSButton {
	Left,
	Middle,
	Right,
}

#[derive(Debug, Clone, PartialEq, FromRepr)]
#[repr(u8)]
pub enum KBKey {
	Esc,
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
