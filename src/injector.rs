use std::ffi::CString;
use std::io::Result;
use winapi::um::memoryapi::VirtualFreeEx;
use winapi::um::winnt::MEM_RELEASE;
use crate::process_manager::{ProcessManager, RemoteProcess};

pub struct DllInjector {
	pub dll_path: CString,
}

impl DllInjector {
	pub fn new(dll_path: &str) -> Self {
		DllInjector {
			dll_path: CString::new(dll_path).expect("Failed to create CString"),
		}
	}

	pub fn inject(&self, process: &RemoteProcess) -> Result<()> {
		let remote_mem = RemoteProcess::allocate_memory(process.handle, &self.dll_path)?;

		match RemoteProcess::write_memory(process.handle, remote_mem, &self.dll_path)
			.and_then(|_| process.create_remote_thread(remote_mem))
		{
			Ok(_) => Ok(()),
			Err(err) => {
				unsafe { VirtualFreeEx(process.handle, remote_mem, 0, MEM_RELEASE) };
				Err(err)
			}
		}
	}
}
