use crate::client::backend::InputEndpoint;
use crate::message::Message;
use crate::{KBKey, MSButton};
use evdev_rs::enums::{EventCode, EventType, EV_KEY, EV_REL, EV_SYN};
use evdev_rs::uinput::UInputDevice;
use evdev_rs::{DeviceWrapper, InputEvent, TimeVal, UninitDevice};
use std::time::SystemTime;
use strum::IntoEnumIterator;

pub struct UInputEndpoint {
	virtual_device: UInputDevice,
}

// TODO: is this safe?
unsafe impl Send for UInputEndpoint {}
unsafe impl Sync for UInputEndpoint {}

impl UInputEndpoint {
	pub fn new() -> Result<Box<dyn InputEndpoint + Send + Sync>, String> {
		let device_template = UninitDevice::new().unwrap();
		device_template.set_name("boundless");
		device_template.set_vendor_id(0x626e);
		device_template.set_product_id(0x646c);
		device_template.set_version(0x1234);
		device_template.set_bustype(3);

		for enable_event in [EventType::EV_SYN, EventType::EV_KEY, EventType::EV_REL, EventType::EV_MSC] {
			if let Err(_) = device_template.enable_event_type(&enable_event) {
				return Err(format!("Failed to enable event type: {:?}", enable_event));
			}
		}

		let mut enable_codes = vec![
			EventCode::EV_SYN(EV_SYN::SYN_REPORT),
			EventCode::EV_SYN(EV_SYN::SYN_CONFIG),
			EventCode::EV_SYN(EV_SYN::SYN_MT_REPORT),
			EventCode::EV_SYN(EV_SYN::SYN_DROPPED),
			EventCode::EV_SYN(EV_SYN::SYN_MAX),
			// EventCode::EV_KEY(EV_KEY::BTN_SIDE),
			// EventCode::EV_KEY(EV_KEY::BTN_EXTRA),
			EventCode::EV_REL(EV_REL::REL_Y),
			EventCode::EV_REL(EV_REL::REL_X),
			EventCode::EV_REL(EV_REL::REL_WHEEL),
			EventCode::EV_REL(EV_REL::REL_WHEEL_HI_RES),
		];

		for key in KBKey::iter() {
			enable_codes.push(EventCode::EV_KEY(map_key(key)));
		}

		for button in MSButton::iter() {
			enable_codes.push(EventCode::EV_KEY(map_button(button)));
		}

		for enable_code in enable_codes {
			if let Err(_) = device_template.enable_event_code(&enable_code, None) {
				return Err(format!("Failed to enable event code: {:?}", enable_code));
			}
		}

		let virtual_device = match UInputDevice::create_from_device(&device_template) {
			Ok(ok) => ok,
			Err(e) => return Err(format!("Failed to create UInput device: {}", e)),
		};

		Ok(Box::new(Self {
			virtual_device,
		}))
	}

	#[inline(always)]
	fn write_event<V: Into<i32>>(&self, code: EventCode, val: V) -> Result<(), String> {
		self.virtual_device.write_event(&event_now(code, val.into())).map_err(|e| format!("{}", e))
	}

	#[inline(always)]
	fn report(&self) -> Result<(), String> {
		self.write_event(EventCode::EV_SYN(EV_SYN::SYN_REPORT), 0)
	}
}

impl InputEndpoint for UInputEndpoint {
	fn send_message(&self, message: Message) -> Result<(), String> {
		match message {
			Message::MSPress(button) => {
				self.write_event(EventCode::EV_KEY(map_button(button)), 1)?;
				self.report()
			},
			Message::MSRelease(button) => {
				self.write_event(EventCode::EV_KEY(map_button(button)), 0)?;
				self.report()
			},
			Message::MSMotion(x, y) => {
				self.write_event(EventCode::EV_REL(EV_REL::REL_X), x)?;
				self.write_event(EventCode::EV_REL(EV_REL::REL_Y), y)?;
				self.report()
			},
			Message::MSScrollV(amt) => {
				self.write_event(EventCode::EV_REL(EV_REL::REL_WHEEL), amt)?;
				self.report()
			},
			Message::MSScrollH(amt) => {
				println!("Unimplemented Event: Message::MSScrollH({})", amt);
				Ok(())
			},
			Message::KBPress(key) => {
				self.write_event(EventCode::EV_KEY(map_key(key)), 1)?;
				self.report()
			},
			Message::KBRelease(key) => {
				self.write_event(EventCode::EV_KEY(map_key(key)), 0)?;
				self.report()
			},
			_ => Ok(()),
		}
	}
}

fn event_now(code: EventCode, value: i32) -> InputEvent {
	let epoc = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
	let epocf = epoc.as_secs_f64();
	let usec = (epocf.fract() / 0.000001).trunc() as i64;
	let sec = epocf.trunc() as i64;
	InputEvent::new(&TimeVal::new(sec, usec), &code, value)
}

fn map_button(button: MSButton) -> EV_KEY {
	match button {
		MSButton::Left => EV_KEY::BTN_LEFT,
		MSButton::Middle => EV_KEY::BTN_MIDDLE,
		MSButton::Right => EV_KEY::BTN_RIGHT,
	}
}

fn map_key(key: KBKey) -> EV_KEY {
	match key {
		KBKey::Esc => EV_KEY::KEY_ESC,
		KBKey::Grave => EV_KEY::KEY_GRAVE,
		KBKey::One => EV_KEY::KEY_1,
		KBKey::Two => EV_KEY::KEY_2,
		KBKey::Three => EV_KEY::KEY_3,
		KBKey::Four => EV_KEY::KEY_4,
		KBKey::Five => EV_KEY::KEY_5,
		KBKey::Six => EV_KEY::KEY_6,
		KBKey::Seven => EV_KEY::KEY_7,
		KBKey::Eight => EV_KEY::KEY_8,
		KBKey::Nine => EV_KEY::KEY_9,
		KBKey::Zero => EV_KEY::KEY_0,
		KBKey::Minus => EV_KEY::KEY_MINUS,
		KBKey::Equal => EV_KEY::KEY_EQUAL,
		KBKey::Backspace => EV_KEY::KEY_BACKSPACE,
		KBKey::Tab => EV_KEY::KEY_TAB,
		KBKey::Q => EV_KEY::KEY_Q,
		KBKey::W => EV_KEY::KEY_W,
		KBKey::E => EV_KEY::KEY_E,
		KBKey::R => EV_KEY::KEY_R,
		KBKey::T => EV_KEY::KEY_T,
		KBKey::Y => EV_KEY::KEY_Y,
		KBKey::U => EV_KEY::KEY_U,
		KBKey::I => EV_KEY::KEY_I,
		KBKey::O => EV_KEY::KEY_O,
		KBKey::P => EV_KEY::KEY_P,
		KBKey::LeftBrace => EV_KEY::KEY_LEFTBRACE,
		KBKey::RightBrace => EV_KEY::KEY_RIGHTBRACE,
		KBKey::Backslash => EV_KEY::KEY_BACKSLASH,
		KBKey::CapsLock => EV_KEY::KEY_CAPSLOCK,
		KBKey::A => EV_KEY::KEY_A,
		KBKey::S => EV_KEY::KEY_S,
		KBKey::D => EV_KEY::KEY_D,
		KBKey::F => EV_KEY::KEY_F,
		KBKey::G => EV_KEY::KEY_G,
		KBKey::H => EV_KEY::KEY_H,
		KBKey::J => EV_KEY::KEY_J,
		KBKey::K => EV_KEY::KEY_K,
		KBKey::L => EV_KEY::KEY_L,
		KBKey::SemiColon => EV_KEY::KEY_SEMICOLON,
		KBKey::Apostrophe => EV_KEY::KEY_APOSTROPHE,
		KBKey::Enter => EV_KEY::KEY_ENTER,
		KBKey::LeftShift => EV_KEY::KEY_LEFTSHIFT,
		KBKey::Z => EV_KEY::KEY_Z,
		KBKey::X => EV_KEY::KEY_X,
		KBKey::C => EV_KEY::KEY_C,
		KBKey::V => EV_KEY::KEY_V,
		KBKey::B => EV_KEY::KEY_B,
		KBKey::N => EV_KEY::KEY_N,
		KBKey::M => EV_KEY::KEY_M,
		KBKey::Comma => EV_KEY::KEY_COMMA,
		KBKey::Dot => EV_KEY::KEY_DOT,
		KBKey::Slash => EV_KEY::KEY_SLASH,
		KBKey::RightShift => EV_KEY::KEY_RIGHTSHIFT,
		KBKey::LeftControl => EV_KEY::KEY_LEFTCTRL,
		KBKey::LeftMeta => EV_KEY::KEY_LEFTMETA,
		KBKey::RightMeta => EV_KEY::KEY_RIGHTMETA,
		KBKey::LeftAlt => EV_KEY::KEY_LEFTALT,
		KBKey::Space => EV_KEY::KEY_SPACE,
		KBKey::RightAlt => EV_KEY::KEY_RIGHTALT,
		KBKey::Fn => EV_KEY::KEY_FN,
		KBKey::RightControl => EV_KEY::KEY_RIGHTCTRL,
		KBKey::Insert => EV_KEY::KEY_INSERT,
		KBKey::Delete => EV_KEY::KEY_DELETE,
		KBKey::PageUp => EV_KEY::KEY_PAGEUP,
		KBKey::PageDown => EV_KEY::KEY_PAGEDOWN,
		KBKey::Sysrq => EV_KEY::KEY_SYSRQ,
		KBKey::ScrollLock => EV_KEY::KEY_SCROLLLOCK,
		KBKey::Pause => EV_KEY::KEY_PAUSE,
		KBKey::Home => EV_KEY::KEY_HOME,
		KBKey::End => EV_KEY::KEY_END,
		KBKey::ArrowUp => EV_KEY::KEY_UP,
		KBKey::ArrowDown => EV_KEY::KEY_DOWN,
		KBKey::ArrowLeft => EV_KEY::KEY_LEFT,
		KBKey::ArrowRight => EV_KEY::KEY_RIGHT,
		KBKey::F1 => EV_KEY::KEY_FN_F1,
		KBKey::F2 => EV_KEY::KEY_FN_F2,
		KBKey::F3 => EV_KEY::KEY_FN_F3,
		KBKey::F4 => EV_KEY::KEY_FN_F4,
		KBKey::F5 => EV_KEY::KEY_FN_F5,
		KBKey::F6 => EV_KEY::KEY_FN_F6,
		KBKey::F7 => EV_KEY::KEY_FN_F7,
		KBKey::F8 => EV_KEY::KEY_FN_F8,
		KBKey::F9 => EV_KEY::KEY_FN_F9,
		KBKey::F10 => EV_KEY::KEY_FN_F10,
		KBKey::F11 => EV_KEY::KEY_FN_F11,
		KBKey::F12 => EV_KEY::KEY_FN_F12,
	}
}
