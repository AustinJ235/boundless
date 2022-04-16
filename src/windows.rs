use crate::server::Capture;
use crate::{KBMSEvent, MSButton, KBKey};
use crossbeam::queue::SegQueue;
use parking_lot::{Condvar, Mutex};
use std::sync::atomic::{self, AtomicBool, AtomicIsize};
use std::sync::Arc;
use std::thread;
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::UI::WindowsAndMessaging::{
	CallNextHookEx, GetMessageW, SetWindowsHookExW, UnhookWindowsHookEx, HHOOK,
	KBDLLHOOKSTRUCT, MSG, MSLLHOOKSTRUCT, WH_KEYBOARD_LL, WH_MOUSE_LL, WM_KEYDOWN, WM_KEYUP,
	WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP, WM_MOUSEHWHEEL, WM_MOUSEMOVE,
	WM_MOUSEWHEEL, WM_RBUTTONDOWN, WM_RBUTTONUP, WM_SYSKEYDOWN, WM_SYSKEYUP,
};

static PASS_EVENTS: AtomicBool = AtomicBool::new(true);
static HOOK_MOUSE_LL: AtomicIsize = AtomicIsize::new(0);
static HOOK_KEYBOARD_LL: AtomicIsize = AtomicIsize::new(0);
static EVENT_QUEUE: SegQueue<KBMSEvent> = SegQueue::new();

unsafe extern "system" fn mouse_ll_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
	if code >= 0 {
		let event_op = match wparam.0 as u32 {
			WM_LBUTTONDOWN => Some(KBMSEvent::MSPress(MSButton::Left)),
			WM_LBUTTONUP => Some(KBMSEvent::MSRelease(MSButton::Left)),
			WM_RBUTTONDOWN => Some(KBMSEvent::MSPress(MSButton::Right)),
			WM_RBUTTONUP => Some(KBMSEvent::MSRelease(MSButton::Right)),
			WM_MBUTTONDOWN => Some(KBMSEvent::MSPress(MSButton::Middle)),
			WM_MBUTTONUP => Some(KBMSEvent::MSRelease(MSButton::Middle)),
			WM_MOUSEMOVE =>
				Some(KBMSEvent::MSMove(
					*(lparam.0 as *const i32),
					*(lparam.0 as *const i32).offset(1),
				)),
			WM_MOUSEWHEEL =>
				Some(KBMSEvent::MSScrollV(
					((*(lparam.0 as *const MSLLHOOKSTRUCT)).mouseData.0 as i32 >> 16) as i16,
				)),
			WM_MOUSEHWHEEL =>
				Some(KBMSEvent::MSScrollH(
					((*(lparam.0 as *const MSLLHOOKSTRUCT)).mouseData.0 as i32 >> 16) as i16,
				)),
			unknown => {
				println!("Unknown WPARAM({}) for MOUSE_LL", unknown);
				None
			},
		};

		if !PASS_EVENTS.load(atomic::Ordering::SeqCst) {
			if event_op.is_some() {
				let event = event_op.unwrap();
				EVENT_QUEUE.push(event);
			}

			return LRESULT(1);
		}
	}

	CallNextHookEx(HHOOK(HOOK_MOUSE_LL.load(atomic::Ordering::SeqCst)), code, wparam, lparam)
}

fn vkcode_to_kbkey(code: u32) -> Option<KBKey> {
	use windows::Win32::UI::Input::KeyboardAndMouse::*;

	Some(match VIRTUAL_KEY(code as _) {
		VK_BACK => KBKey::Backspace,
		VK_TAB => KBKey::Tab,
		VK_RETURN => KBKey::Enter,
		VK_PAUSE => KBKey::Pause,
		VK_CAPITAL => KBKey::CapsLock,
		VK_ESCAPE => KBKey::Esc,
		VK_SPACE => KBKey::Space,
		VK_PRIOR => KBKey::PageUp,
		VK_NEXT => KBKey::PageDown,
		VK_END => KBKey::End,
		VK_HOME => KBKey::Home,
		VK_LEFT => KBKey::ArrowLeft,
		VK_UP => KBKey::ArrowUp,
		VK_RIGHT => KBKey::ArrowRight,
		VK_DOWN => KBKey::ArrowDown,
		VK_SNAPSHOT => KBKey::Sysrq,
		VK_INSERT => KBKey::Insert,
		VK_DELETE => KBKey::Delete,
		VK_LWIN => KBKey::LeftMeta,
		VK_RWIN => KBKey::RightMeta,
		VK_SCROLL => KBKey::ScrollLock,
		VK_LSHIFT => KBKey::LeftShift,
		VK_RSHIFT => KBKey::RightShift,
		VK_LCONTROL => KBKey::LeftControl,
		VK_RCONTROL => KBKey::RightControl,
		VK_RMENU => KBKey::RightAlt,
		VK_LMENU => KBKey::LeftAlt,
		VIRTUAL_KEY(0x0030) => KBKey::Zero,
		VIRTUAL_KEY(0x0031) => KBKey::One,
		VIRTUAL_KEY(0x0032) => KBKey::Two,
		VIRTUAL_KEY(0x0033) => KBKey::Three,
		VIRTUAL_KEY(0x0034) => KBKey::Four,
		VIRTUAL_KEY(0x0035) => KBKey::Five,
		VIRTUAL_KEY(0x0036) => KBKey::Six,
		VIRTUAL_KEY(0x0037) => KBKey::Seven,
		VIRTUAL_KEY(0x0038) => KBKey::Eight,
		VIRTUAL_KEY(0x0039) => KBKey::Nine,
		VK_OEM_MINUS => KBKey::Minus,
		VK_OEM_PLUS => KBKey::Equal,
		VIRTUAL_KEY(0x0051) => KBKey::Q,
		VIRTUAL_KEY(0x0057) => KBKey::W,
		VIRTUAL_KEY(0x0045) => KBKey::E,
		VIRTUAL_KEY(0x0052) => KBKey::R,
		VIRTUAL_KEY(0x0054) => KBKey::T,
		VIRTUAL_KEY(0x0059) => KBKey::Y,
		VIRTUAL_KEY(0x0055) => KBKey::U,
		VIRTUAL_KEY(0x0049) => KBKey::I,
		VIRTUAL_KEY(0x004F) => KBKey::O,
		VIRTUAL_KEY(0x0050) => KBKey::P,
		VK_OEM_4 => KBKey::LeftBrace,
		VK_OEM_6 => KBKey::RightBrace,
		VK_OEM_5 => KBKey::Backslash,
		//VIRTUAL_KEY(0x00) => KBKey::,
		//VIRTUAL_KEY(0x00) => KBKey::,
		//VIRTUAL_KEY(0x00) => KBKey::,
		c => {
			println!("Unknown Virtual-Key: {:#06x}", c.0);
			return None
		},
	})
}

unsafe extern "system" fn keyboard_ll_hook(
	code: i32,
	wparam: WPARAM,
	lparam: LPARAM,
) -> LRESULT {
	if code >= 0 {
		let info = *(lparam.0 as *const KBDLLHOOKSTRUCT);
		let pass_events = PASS_EVENTS.load(atomic::Ordering::SeqCst);

		let event_op: Option<KBMSEvent> = match wparam.0 as u32 {
			WM_KEYDOWN | WM_SYSKEYDOWN => vkcode_to_kbkey(info.vkCode).map(|v| KBMSEvent::KBPress(v)),
			WM_KEYUP | WM_SYSKEYUP => vkcode_to_kbkey(info.vkCode).map(|v| KBMSEvent::KBRelease(v)),
			unknown => {
				println!("Unknown WPARAM({}) for KEYBOARD_LL", unknown);
				None
			},
		};

		if event_op.is_none() {
			if !pass_events {
				return LRESULT(1);
			}
		} else {
			let event = event_op.unwrap();

			if event == KBMSEvent::KBPress(KBKey::RightControl) {
				return LRESULT(1);
			}

			if event == KBMSEvent::KBRelease(KBKey::RightControl) {
				PASS_EVENTS.store(!pass_events, atomic::Ordering::SeqCst);

				if pass_events {
					EVENT_QUEUE.push(KBMSEvent::CaptureStart);
				} else {
					EVENT_QUEUE.push(KBMSEvent::CaptureEnd);
				}

				return LRESULT(1);
			}

			if !pass_events {
				EVENT_QUEUE.push(event);
				return LRESULT(1);
			}
		}
	}

	CallNextHookEx(HHOOK(HOOK_KEYBOARD_LL.load(atomic::Ordering::SeqCst)), code, wparam, lparam)
}

pub struct WindowsCapture {}

impl WindowsCapture {
	pub fn new() -> Result<Box<dyn Capture>, String> {
		let startup_result: Arc<Mutex<Option<Result<(), String>>>> = Arc::new(Mutex::new(None));
		let startup_result_ready = Arc::new(Condvar::new());
		let thread_result = startup_result.clone();
		let thread_result_ready = startup_result_ready.clone();

		thread::spawn(move || unsafe {
			let hook_mouse_ll = match SetWindowsHookExW(
				WH_MOUSE_LL,
				Some(mouse_ll_hook),
				HINSTANCE::default(),
				0,
			) {
				Ok(ok) =>
					match ok.is_invalid() {
						true => {
							*thread_result.lock() = Some(Err(String::from(
								"SetWindowsHookExW for WH_MOUSE_LL was successful, but \
								 returned handle is invalid.",
							)));
							thread_result_ready.notify_one();
							return;
						},
						false => ok,
					},
				Err(e) => {
					*thread_result.lock() = Some(Err(format!(
						"SetWindowsHookExW for WH_MOUSE_LL return an error: {}",
						e
					)));
					thread_result_ready.notify_one();
					return;
				},
			};

			let hook_keyboard_ll = match SetWindowsHookExW(
				WH_KEYBOARD_LL,
				Some(keyboard_ll_hook),
				HINSTANCE::default(),
				0,
			) {
				Ok(ok) =>
					match ok.is_invalid() {
						true => {
							*thread_result.lock() = Some(Err(String::from(
								"SetWindowsHookExW for WH_KEYBOARD_LL was successful, but \
								 returned handle is invalid.",
							)));
							thread_result_ready.notify_one();
							UnhookWindowsHookEx(hook_mouse_ll);
							return;
						},
						false => ok,
					},
				Err(e) => {
					*thread_result.lock() = Some(Err(format!(
						"SetWindowsHookExW for WH_KEYBOARD_LL return an error: {}",
						e
					)));
					thread_result_ready.notify_one();
					UnhookWindowsHookEx(hook_mouse_ll);
					return;
				},
			};

			HOOK_MOUSE_LL.store(hook_mouse_ll.0, atomic::Ordering::SeqCst);
			HOOK_KEYBOARD_LL.store(hook_keyboard_ll.0, atomic::Ordering::SeqCst);
			*thread_result.lock() = Some(Ok(()));
			thread_result_ready.notify_one();
			let mut message = MSG::default();

			loop {
				match GetMessageW(&mut message, HWND::default(), 0, 0).ok() {
					Ok(_) =>
						match message.message {
							_ => {
								println!("[MSG]: UNKNOWN: {:?}", message);
							},
						},
					Err(e) => {
						println!("[MSG]: ERROR: {}", e);
						break;
					},
				}
			}

			UnhookWindowsHookEx(hook_mouse_ll);
			UnhookWindowsHookEx(hook_keyboard_ll);
		});

		let mut result_lk = startup_result.lock();

		while result_lk.is_none() {
			startup_result_ready.wait(&mut result_lk);
		}

		result_lk.take().unwrap()?;

		Ok(Box::new(Self {}))
	}
}

impl Capture for WindowsCapture {
	fn event_queue(&self) -> &SegQueue<KBMSEvent> {
		&EVENT_QUEUE
	}
}
