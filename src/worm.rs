use parking_lot::{Condvar, Mutex, Once, OnceState};
use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::ops::Deref;
use std::time::Duration;

pub struct Worm<T: Send + Sync> {
	once: Once,
	init: Mutex<bool>,
	cond: Condvar,
	cell: UnsafeCell<MaybeUninit<T>>,
}

unsafe impl<T: Send + Sync> Send for Worm<T> {}
unsafe impl<T: Send + Sync> Sync for Worm<T> {}

impl<T: Send + Sync> Worm<T> {
	pub fn new() -> Self {
		Self {
			once: Once::new(),
			init: Mutex::new(false),
			cond: Condvar::new(),
			cell: UnsafeCell::new(MaybeUninit::uninit()),
		}
	}

	pub fn write(&self, val: T) {
		match self.once.state() {
			OnceState::New => unsafe {
				self.write_unchecked(val);
				*self.init.lock() = true;
				self.cond.notify_all();
			},
			OnceState::Poisoned => unreachable!(),
			OnceState::InProgress | OnceState::Done => panic!("Worm already initialized!"),
		}
	}

	pub fn try_write(&self, val: T) -> Result<(), T> {
		match self.once.state() {
			OnceState::New => unsafe {
				self.write_unchecked(val);
				*self.init.lock() = true;
				self.cond.notify_all();
				Ok(())
			},
			OnceState::Poisoned => unreachable!(),
			OnceState::InProgress | OnceState::Done => Err(val),
		}
	}

	#[inline(always)]
	unsafe fn write_unchecked(&self, val: T) {
		self.once.call_once(|| {
			(*self.cell.get()).write(val);
		});
	}

	pub fn wait_for_write(&self) {
		let mut init = self.init.lock();

		if *init {
			return;
		}

		self.cond.wait(&mut init);
	}

	pub fn wait_for_write_timeout(&self, timeout: Duration) -> Result<(), ()> {
		let mut init = self.init.lock();

		if *init {
			return Ok(());
		}

		self.cond.wait_for(&mut init, timeout);

		if *init {
			Ok(())
		} else {
			Err(())
		}
	}

	pub fn read(&self) -> &T {
		match self.once.state() {
			OnceState::New => panic!("Worm is not initialized!"),
			OnceState::Poisoned => unreachable!(),
			OnceState::InProgress => self.wait_for_write(),
			OnceState::Done => (),
		}

		unsafe { self.read_unchecked() }
	}

	pub fn blocking_read(&self) -> &T {
		match self.try_read() {
			Ok(ok) => ok,
			Err(_) => {
				self.wait_for_write();
				self.read()
			},
		}
	}

	pub fn blocking_read_timeout(&self, timeout: Duration) -> Result<&T, ()> {
		match self.try_read() {
			Ok(ok) => Ok(ok),
			Err(_) =>
				match self.wait_for_write_timeout(timeout) {
					Ok(_) => Ok(self.read()),
					Err(_) => Err(()),
				},
		}
	}

	pub fn try_read(&self) -> Result<&T, ()> {
		match self.once.state() {
			OnceState::New => return Err(()),
			OnceState::Poisoned => unreachable!(),
			OnceState::InProgress =>
				while self.once.state() != OnceState::Done {
					std::hint::spin_loop();
				},
			OnceState::Done => (),
		}

		unsafe { Ok(self.read_unchecked()) }
	}

	#[inline(always)]
	unsafe fn read_unchecked(&self) -> &T {
		(&*self.cell.get()).assume_init_ref()
	}
}

impl<T: Send + Sync> Drop for Worm<T> {
	fn drop(&mut self) {
		if self.once.state().done() {
			unsafe { (&mut *self.cell.get_mut()).assume_init_drop() }
		}
	}
}

impl<T: Send + Sync> Deref for Worm<T> {
	type Target = T;

	fn deref(&self) -> &Self::Target {
		self.read()
	}
}
