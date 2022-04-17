use crate::server::Capture;
use crate::{KBKey, KBMSEvent, MSButton};
use crossbeam::queue::SegQueue;
use parking_lot::{Condvar, Mutex};
use std::sync::atomic::{self, AtomicBool, AtomicIsize};
use std::sync::Arc;
use std::thread;
use u16cstr::u16cstr;
use widestring::U16CStr;
use windows::core::PCWSTR;
use windows::Win32::Devices::HumanInterfaceDevice::{
	HID_USAGE_GENERIC_MOUSE, HID_USAGE_PAGE_GENERIC, MOUSE_MOVE_RELATIVE,
};
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::HBRUSH;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::{
	VIRTUAL_KEY, VK_BACK, VK_CAPITAL, VK_DELETE, VK_DOWN, VK_END, VK_ESCAPE, VK_F1, VK_F10,
	VK_F11, VK_F12, VK_F2, VK_F3, VK_F4, VK_F5, VK_F6, VK_F7, VK_F8, VK_F9, VK_HOME, VK_INSERT,
	VK_LCONTROL, VK_LEFT, VK_LMENU, VK_LSHIFT, VK_LWIN, VK_NEXT, VK_OEM_1, VK_OEM_2, VK_OEM_4,
	VK_OEM_5, VK_OEM_6, VK_OEM_7, VK_OEM_COMMA, VK_OEM_MINUS, VK_OEM_PERIOD, VK_OEM_PLUS,
	VK_PAUSE, VK_PRIOR, VK_RCONTROL, VK_RETURN, VK_RIGHT, VK_RMENU, VK_RSHIFT, VK_RWIN,
	VK_SCROLL, VK_SNAPSHOT, VK_SPACE, VK_TAB, VK_UP,
};
use windows::Win32::UI::Input::{
	GetRawInputData, RegisterRawInputDevices, HRAWINPUT, RAWINPUT, RAWINPUTDEVICE,
	RAWINPUTHEADER, RIDEV_INPUTSINK, RIDEV_NOLEGACY, RID_DEVICE_INFO_TYPE, RID_INPUT,
	RIM_TYPEMOUSE,
};
use windows::Win32::UI::WindowsAndMessaging::{
	CallNextHookEx, CreateWindowExW, DefWindowProcW, GetMessageW, GetShellWindow,
	RegisterClassExW, SetWindowLongPtrW, SetWindowsHookExW, UnhookWindowsHookEx, GWL_STYLE,
	HCURSOR, HHOOK, HICON, HMENU, KBDLLHOOKSTRUCT, MSG, MSLLHOOKSTRUCT, WH_KEYBOARD_LL,
	WH_MOUSE_LL, WM_INPUT, WM_KEYDOWN, WM_KEYUP, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDOWN,
	WM_MBUTTONUP, WM_MOUSEHWHEEL, WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_RBUTTONDOWN, WM_RBUTTONUP,
	WM_SYSKEYDOWN, WM_SYSKEYUP, WNDCLASSEXW, WNDCLASS_STYLES, WS_EX_LAYERED, WS_EX_NOACTIVATE,
	WS_EX_TOOLWINDOW, WS_EX_TRANSPARENT, WS_OVERLAPPED, WS_POPUP, WS_VISIBLE,
};

const WINPROC_CLASS_NAME: &'static U16CStr = u16cstr!("Boundless Raw Input");
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
			WM_MOUSEMOVE => None, // TODO: Maybe use this in the future???
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

#[inline(always)]
fn vkcode_to_kbkey(code: u32) -> Option<KBKey> {
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
		VK_F1 => KBKey::F1,
		VK_F2 => KBKey::F2,
		VK_F3 => KBKey::F3,
		VK_F4 => KBKey::F4,
		VK_F5 => KBKey::F5,
		VK_F6 => KBKey::F6,
		VK_F7 => KBKey::F7,
		VK_F8 => KBKey::F8,
		VK_F9 => KBKey::F9,
		VK_F10 => KBKey::F10,
		VK_F11 => KBKey::F11,
		VK_F12 => KBKey::F12,
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
		VIRTUAL_KEY(0x0041) => KBKey::A,
		VIRTUAL_KEY(0x0053) => KBKey::S,
		VIRTUAL_KEY(0x0044) => KBKey::D,
		VIRTUAL_KEY(0x0046) => KBKey::F,
		VIRTUAL_KEY(0x0047) => KBKey::G,
		VIRTUAL_KEY(0x0048) => KBKey::H,
		VIRTUAL_KEY(0x004A) => KBKey::J,
		VIRTUAL_KEY(0x004B) => KBKey::K,
		VIRTUAL_KEY(0x004C) => KBKey::L,
		VK_OEM_1 => KBKey::SemiColon,
		VK_OEM_7 => KBKey::Apostrophe,
		VIRTUAL_KEY(0x005A) => KBKey::Z,
		VIRTUAL_KEY(0x0058) => KBKey::X,
		VIRTUAL_KEY(0x0043) => KBKey::C,
		VIRTUAL_KEY(0x0056) => KBKey::V,
		VIRTUAL_KEY(0x0042) => KBKey::B,
		VIRTUAL_KEY(0x004E) => KBKey::N,
		VIRTUAL_KEY(0x004D) => KBKey::M,
		VK_OEM_COMMA => KBKey::Comma,
		VK_OEM_PERIOD => KBKey::Dot,
		VK_OEM_2 => KBKey::Slash,
		c => {
			println!("Unknown Virtual-Key: {:#06x}", c.0);
			return None;
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
			WM_KEYDOWN | WM_SYSKEYDOWN =>
				vkcode_to_kbkey(info.vkCode).map(|v| KBMSEvent::KBPress(v)),
			WM_KEYUP | WM_SYSKEYUP =>
				vkcode_to_kbkey(info.vkCode).map(|v| KBMSEvent::KBRelease(v)),
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

unsafe extern "system" fn wnd_proc_callback(
	window: HWND,
	msg: u32,
	wparam: WPARAM,
	lparam: LPARAM,
) -> LRESULT {
	println!("Window Proc MSG: {:#04x}", msg);
	// println!("window: {:?}, msg: {}, wparam: {:?}, lparam: {:?}", window, msg, wparam,
	// lparam);
	DefWindowProcW(window, msg, wparam, lparam)
}

pub struct WindowsCapture {}

impl WindowsCapture {
	pub fn new() -> Result<Box<dyn Capture>, String> {
		let startup_result: Arc<Mutex<Option<Result<(), String>>>> = Arc::new(Mutex::new(None));
		let startup_result_ready = Arc::new(Condvar::new());
		let thread_result = startup_result.clone();
		let thread_result_ready = startup_result_ready.clone();

		thread::spawn(move || unsafe {
			let target_win_class = WNDCLASSEXW {
				cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
				style: WNDCLASS_STYLES(0),
				lpfnWndProc: Some(wnd_proc_callback),
				cbClsExtra: 0,
				cbWndExtra: 0,
				hInstance: GetModuleHandleW(PCWSTR::default()),
				hIcon: HICON(0),
				hCursor: HCURSOR(0), // must be null in order for cursor state to work properly
				hbrBackground: HBRUSH(0),
				lpszMenuName: PCWSTR::default(),
				lpszClassName: PCWSTR(WINPROC_CLASS_NAME.as_ptr()),
				hIconSm: HICON(0),
			};

			RegisterClassExW(&target_win_class);

			let hwnd = CreateWindowExW(
				WS_EX_NOACTIVATE | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_TOOLWINDOW,
				PCWSTR(WINPROC_CLASS_NAME.as_ptr()),
				PCWSTR::default(),
				WS_OVERLAPPED,
				0,
				0,
				0,
				0,
				HWND(0),
				HMENU(0),
				GetModuleHandleW(PCWSTR::default()),
				std::ptr::null(),
			);

			SetWindowLongPtrW(hwnd, GWL_STYLE, (WS_VISIBLE | WS_POPUP).0 as isize);

			if hwnd.0 == 0 {
				*thread_result.lock() =
					Some(Err(String::from("Failed to create event target window.")));
				thread_result_ready.notify_one();
				return;
			}

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

			println!("register");

			let raw_devices = [RAWINPUTDEVICE {
				usUsagePage: HID_USAGE_PAGE_GENERIC,
				usUsage: HID_USAGE_GENERIC_MOUSE,
				dwFlags: RIDEV_NOLEGACY | RIDEV_INPUTSINK,
				hwndTarget: hwnd,
			}];

			if let Err(e) = RegisterRawInputDevices(
				&raw_devices,
				std::mem::size_of::<RAWINPUTDEVICE>() as u32,
			)
			.ok()
			{
				*thread_result.lock() =
					Some(Err(format!("Failed to register raw input devices: {}", e)));
				thread_result_ready.notify_one();
				UnhookWindowsHookEx(hook_mouse_ll);
				UnhookWindowsHookEx(hook_keyboard_ll);
				return;
			}

			*thread_result.lock() = Some(Ok(()));
			thread_result_ready.notify_one();
			let mut message = MSG::default();

			loop {
				match GetMessageW(&mut message, HWND::default(), 0, 0).ok() {
					Ok(_) =>
						match message.message {
							WM_INPUT => {
								let mut data: RAWINPUT = std::mem::zeroed();
								let mut data_size = std::mem::size_of::<RAWINPUT>() as u32;

								match GetRawInputData(
									std::mem::transmute::<_, HRAWINPUT>(message.lParam),
									RID_INPUT,
									&mut data as *mut _ as _,
									&mut data_size,
									std::mem::size_of::<RAWINPUTHEADER>() as u32,
								) {
									u32::MAX | 0 => {
										println!("GetRawInputData Failed");
										continue;
									},
									_ => (),
								}

								match RID_DEVICE_INFO_TYPE(data.header.dwType) {
									RIM_TYPEMOUSE => {
										if !PASS_EVENTS.load(atomic::Ordering::SeqCst) {
											let mouse_data = data.data.mouse;

											if mouse_data.usFlags as u32 | MOUSE_MOVE_RELATIVE
												== MOUSE_MOVE_RELATIVE
											{
												EVENT_QUEUE.push(KBMSEvent::MSMotion(
													mouse_data.lLastX,
													mouse_data.lLastY,
												));
											}
										}
									},
									ty => println!("Uknown raw input type: {:?}", ty),
								}
							},
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
