#[cfg(target_os = "windows")]
pub mod windows;
pub mod server;

#[derive(Debug, Clone, PartialEq)]
pub enum KBMSEvent {
	MSPress(MSButton),
	MSRelease(MSButton),
	MSMove(i32, i32),
	MSScrollV(i16),
	MSScrollH(i16),
	KBPress(u32),
	KBRelease(u32),
    CaptureStart,
    CaptureEnd,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MSButton {
	Left,
	Middle,
	Right,
}

fn main() {
    let server = match server::Server::new() {
        Ok(ok) => ok,
        Err(e) => {
            println!("Failed to start server: {}", e);
            return;
        }
    };

	loop {
        while let Some(event) = server.next_event() {
            println!("{:?}", event);
        }

        std::thread::sleep(std::time::Duration::from_millis(15));
    }
}
