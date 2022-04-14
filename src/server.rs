use crate::KBMSEvent;
use crossbeam::queue::SegQueue;

pub struct Server {
    capture: Box<dyn Capture>,
}

impl Server {
    pub fn new() -> Result<Self, String> {
        let capture_result: Result<Box<dyn Capture>, String> = {
            #[cfg(target_os = "windows")]
            { crate::windows::WindowsCapture::new() }
            #[cfg(not(target_os = "windows"))]
            { Err(String::from("Platform not supported.")) }
        };

        let capture = match capture_result {
            Ok(ok) => ok,
            Err(e) => return Err(format!("Failed to initiate capture: {}", e))
        };

        Ok(Self {
            capture,
        })
    }

    pub fn next_event(&self) -> Option<KBMSEvent> {
        self.capture.event_queue().pop()
    }
}

pub trait Capture {
    fn event_queue(&self) -> &SegQueue<KBMSEvent>;
}
