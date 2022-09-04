use std::sync::atomic::{self, AtomicBool, AtomicIsize};
use std::sync::{Arc, Weak};
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

use parking_lot::{Condvar, Mutex};
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
    VIRTUAL_KEY, VK_BACK, VK_CAPITAL, VK_DELETE, VK_DOWN, VK_END, VK_ESCAPE, VK_F1, VK_F10, VK_F11,
    VK_F12, VK_F2, VK_F3, VK_F4, VK_F5, VK_F6, VK_F7, VK_F8, VK_F9, VK_HOME, VK_INSERT,
    VK_LCONTROL, VK_LEFT, VK_LMENU, VK_LSHIFT, VK_LWIN, VK_NEXT, VK_OEM_1, VK_OEM_2, VK_OEM_4,
    VK_OEM_5, VK_OEM_6, VK_OEM_7, VK_OEM_COMMA, VK_OEM_MINUS, VK_OEM_PERIOD, VK_OEM_PLUS, VK_PAUSE,
    VK_PRIOR, VK_RCONTROL, VK_RETURN, VK_RIGHT, VK_RMENU, VK_RSHIFT, VK_RWIN, VK_SCROLL,
    VK_SNAPSHOT, VK_SPACE, VK_TAB, VK_UP,
};
use windows::Win32::UI::Input::{
    GetRawInputData, RegisterRawInputDevices, HRAWINPUT, RAWINPUT, RAWINPUTDEVICE, RAWINPUTHEADER,
    RIDEV_INPUTSINK, RIDEV_NOLEGACY, RID_DEVICE_INFO_TYPE, RID_INPUT, RIM_TYPEMOUSE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, CreateWindowExW, DefWindowProcW, GetMessageW, RegisterClassExW,
    SetWindowsHookExW, UnhookWindowsHookEx, HCURSOR, HHOOK, HICON, HMENU, KBDLLHOOKSTRUCT, MSG,
    MSLLHOOKSTRUCT, WH_KEYBOARD_LL, WH_MOUSE_LL, WM_INPUT, WM_KEYDOWN, WM_KEYUP, WM_LBUTTONDOWN,
    WM_LBUTTONUP, WM_MBUTTONDOWN, WM_MBUTTONUP, WM_MOUSEHWHEEL, WM_MOUSEMOVE, WM_MOUSEWHEEL,
    WM_RBUTTONDOWN, WM_RBUTTONUP, WM_SYSKEYDOWN, WM_SYSKEYUP, WNDCLASSEXW, WNDCLASS_STYLES,
    WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TRANSPARENT, WS_OVERLAPPED,
};

use crate::message::Message;
use crate::server::backend::InputSource;
use crate::server::Server;
use crate::worm::Worm;
use crate::{KBKey, MSButton};

const WINPROC_CLASS_NAME: &'static U16CStr = u16cstr!("Boundless Raw Input");
static PASS_EVENTS: AtomicBool = AtomicBool::new(true);
static HOOK_MOUSE_LL: AtomicIsize = AtomicIsize::new(0);
static HOOK_KEYBOARD_LL: AtomicIsize = AtomicIsize::new(0);
static SERVER_OP: Mutex<Option<Weak<Worm<Server>>>> = Mutex::new(None);

fn send_message(msg: Message) -> Result<bool, String> {
    match SERVER_OP.lock().as_ref() {
        Some(weak) => {
            match weak.upgrade() {
                Some(worm) => {
                    match worm.try_read() {
                        Ok(server) => Ok(server.send_message(msg)),
                        Err(_) => Err(String::from("server not intialized")),
                    }
                },
                None => Err(String::from("server has been dropped")),
            }
        },
        None => Err(String::from("server not set")),
    }
}

unsafe extern "system" fn mouse_ll_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 {
        let event_op = match wparam.0 as u32 {
            WM_LBUTTONDOWN => Some(Message::MSPress(MSButton::Left)),
            WM_LBUTTONUP => Some(Message::MSRelease(MSButton::Left)),
            WM_RBUTTONDOWN => Some(Message::MSPress(MSButton::Right)),
            WM_RBUTTONUP => Some(Message::MSRelease(MSButton::Right)),
            WM_MBUTTONDOWN => Some(Message::MSPress(MSButton::Middle)),
            WM_MBUTTONUP => Some(Message::MSRelease(MSButton::Middle)),
            WM_MOUSEMOVE => None,
            WM_MOUSEWHEEL => {
                Some(Message::MSScrollV(
                    ((*(lparam.0 as *const MSLLHOOKSTRUCT)).mouseData.0 as i32 >> 16) as i16 / 120,
                ))
            },
            WM_MOUSEHWHEEL => {
                Some(Message::MSScrollH(
                    ((*(lparam.0 as *const MSLLHOOKSTRUCT)).mouseData.0 as i32 >> 16) as i16 / 120,
                ))
            },
            unknown => {
                println!("Unknown WPARAM({}) for MOUSE_LL", unknown);
                None
            },
        };

        if !PASS_EVENTS.load(atomic::Ordering::SeqCst) {
            if let Some(event) = event_op {
                if send_message(event).unwrap_or(false) {
                    return LRESULT(1);
                } else {
                    PASS_EVENTS.store(true, atomic::Ordering::SeqCst);
                }
            } else {
                return LRESULT(1);
            }
        }
    }

    CallNextHookEx(
        HHOOK(HOOK_MOUSE_LL.load(atomic::Ordering::SeqCst)),
        code,
        wparam,
        lparam,
    )
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
        VIRTUAL_KEY(0x00c0) => KBKey::Grave,
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

unsafe extern "system" fn keyboard_ll_hook(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if code >= 0 {
        let info = *(lparam.0 as *const KBDLLHOOKSTRUCT);
        let pass_events = PASS_EVENTS.load(atomic::Ordering::SeqCst);

        let event_op: Option<Message> = match wparam.0 as u32 {
            WM_KEYDOWN | WM_SYSKEYDOWN => vkcode_to_kbkey(info.vkCode).map(|v| Message::KBPress(v)),
            WM_KEYUP | WM_SYSKEYUP => vkcode_to_kbkey(info.vkCode).map(|v| Message::KBRelease(v)),
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

            if event == Message::KBPress(KBKey::RightControl) {
                return LRESULT(1);
            }

            if event == Message::KBRelease(KBKey::RightControl) {
                PASS_EVENTS.store(!pass_events, atomic::Ordering::SeqCst);
                return LRESULT(1);
            }

            if !pass_events {
                if send_message(event).unwrap_or(false) {
                    return LRESULT(1);
                } else {
                    PASS_EVENTS.store(true, atomic::Ordering::SeqCst);
                }
            }
        }
    }

    CallNextHookEx(
        HHOOK(HOOK_KEYBOARD_LL.load(atomic::Ordering::SeqCst)),
        code,
        wparam,
        lparam,
    )
}

unsafe extern "system" fn wnd_proc_callback(
    window: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    DefWindowProcW(window, msg, wparam, lparam)
}

pub struct Win32Input {
    thrd_h: Mutex<Option<JoinHandle<Result<(), String>>>>,
}

impl Win32Input {
    pub fn new(
        server_wk: Weak<Worm<Server>>,
    ) -> Result<Box<dyn InputSource + Send + Sync>, String> {
        let startup_result: Arc<Mutex<Option<Result<(), String>>>> = Arc::new(Mutex::new(None));
        let startup_result_ready = Arc::new(Condvar::new());
        let thread_result = startup_result.clone();
        let thread_result_ready = startup_result_ready.clone();

        let thrd_h = thread::spawn(move || unsafe {
            let target_win_class = WNDCLASSEXW {
                cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
                style: WNDCLASS_STYLES(0),
                lpfnWndProc: Some(wnd_proc_callback),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: GetModuleHandleW(PCWSTR::default()),
                hIcon: HICON(0),
                hCursor: HCURSOR(0),
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

            if hwnd.0 == 0 {
                *thread_result.lock() =
                    Some(Err(String::from("Failed to create event target window.")));
                thread_result_ready.notify_one();
                return Ok(());
            }

            let hook_mouse_ll = match SetWindowsHookExW(
                WH_MOUSE_LL,
                Some(mouse_ll_hook),
                HINSTANCE::default(),
                0,
            ) {
                Ok(ok) => {
                    match ok.is_invalid() {
                        true => {
                            *thread_result.lock() = Some(Err(String::from(
                                "SetWindowsHookExW for WH_MOUSE_LL was successful, but returned \
                                 handle is invalid.",
                            )));
                            thread_result_ready.notify_one();
                            return Ok(());
                        },
                        false => ok,
                    }
                },
                Err(e) => {
                    *thread_result.lock() = Some(Err(format!(
                        "SetWindowsHookExW for WH_MOUSE_LL return an error: {}",
                        e
                    )));
                    thread_result_ready.notify_one();
                    return Ok(());
                },
            };

            let hook_keyboard_ll = match SetWindowsHookExW(
                WH_KEYBOARD_LL,
                Some(keyboard_ll_hook),
                HINSTANCE::default(),
                0,
            ) {
                Ok(ok) => {
                    match ok.is_invalid() {
                        true => {
                            *thread_result.lock() = Some(Err(String::from(
                                "SetWindowsHookExW for WH_KEYBOARD_LL was successful, but \
                                 returned handle is invalid.",
                            )));
                            thread_result_ready.notify_one();
                            UnhookWindowsHookEx(hook_mouse_ll);
                            return Ok(());
                        },
                        false => ok,
                    }
                },
                Err(e) => {
                    *thread_result.lock() = Some(Err(format!(
                        "SetWindowsHookExW for WH_KEYBOARD_LL return an error: {}",
                        e
                    )));
                    thread_result_ready.notify_one();
                    UnhookWindowsHookEx(hook_mouse_ll);
                    return Ok(());
                },
            };

            HOOK_MOUSE_LL.store(hook_mouse_ll.0, atomic::Ordering::SeqCst);
            HOOK_KEYBOARD_LL.store(hook_keyboard_ll.0, atomic::Ordering::SeqCst);

            let raw_devices = [RAWINPUTDEVICE {
                usUsagePage: HID_USAGE_PAGE_GENERIC,
                usUsage: HID_USAGE_GENERIC_MOUSE,
                dwFlags: RIDEV_NOLEGACY | RIDEV_INPUTSINK,
                hwndTarget: hwnd,
            }];

            if let Err(e) =
                RegisterRawInputDevices(&raw_devices, std::mem::size_of::<RAWINPUTDEVICE>() as u32)
                    .ok()
            {
                *thread_result.lock() =
                    Some(Err(format!("Failed to register raw input devices: {}", e)));
                thread_result_ready.notify_one();
                UnhookWindowsHookEx(hook_mouse_ll);
                UnhookWindowsHookEx(hook_keyboard_ll);
                return Ok(());
            }

            *thread_result.lock() = Some(Ok(()));
            thread_result_ready.notify_one();

            match server_wk.upgrade() {
                Some(worm) => {
                    match worm.blocking_read_timeout(Duration::from_millis(500)) {
                        Ok(_) => *SERVER_OP.lock() = Some(server_wk.clone()),
                        Err(_) => {
                            UnhookWindowsHookEx(hook_mouse_ll);
                            UnhookWindowsHookEx(hook_keyboard_ll);
                            return Ok(());
                        },
                    }
                },
                None => {
                    UnhookWindowsHookEx(hook_mouse_ll);
                    UnhookWindowsHookEx(hook_keyboard_ll);
                    return Ok(());
                },
            }

            let mut message = MSG::default();
            let error_op;

            loop {
                match GetMessageW(&mut message, HWND::default(), 0, 0).ok() {
                    Ok(_) => {
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
                                                if let Err(e) = send_message(Message::MSMotion(
                                                    mouse_data.lLastX,
                                                    mouse_data.lLastY,
                                                )) {
                                                    error_op = Some(e);
                                                    break;
                                                }
                                            }
                                        }
                                    },
                                    ty => println!("Uknown raw input type: {:?}", ty),
                                }
                            },
                            _ => {
                                println!("[MSG]: UNKNOWN: {:?}", message);
                            },
                        }
                    },
                    Err(e) => {
                        error_op = Some(format!("GetMessageW failed with {}", e));
                        break;
                    },
                }
            }

            UnhookWindowsHookEx(hook_mouse_ll);
            UnhookWindowsHookEx(hook_keyboard_ll);

            match error_op {
                Some(some) => Err(some),
                None => Ok(()),
            }
        });

        let mut result_lk = startup_result.lock();

        while result_lk.is_none() {
            startup_result_ready.wait(&mut result_lk);
        }

        result_lk.take().unwrap()?;

        Ok(Box::new(Self {
            thrd_h: Mutex::new(Some(thrd_h)),
        }))
    }
}

impl InputSource for Win32Input {
    fn check_status(&self) -> Result<(), String> {
        let mut handle = self.thrd_h.lock();

        if handle.is_none() {
            return Err(String::from("thread has previously exited"));
        }

        if handle.as_ref().unwrap().is_finished() {
            return match handle.take().unwrap().join() {
                Ok(ok) => {
                    match ok {
                        Ok(_) => Err(String::from("thread has exited sucessfully")),
                        Err(e) => Err(format!("thread has exited with error: {}", e)),
                    }
                },
                Err(_) => Err(String::from("thread has panicked")),
            };
        }

        Ok(())
    }
}
