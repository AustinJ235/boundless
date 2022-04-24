#[cfg(target_family = "unix")]
pub mod uinput;
#[cfg(target_os = "windows")]
pub mod windows;
