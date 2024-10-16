use std::ffi::{CStr, CString};
use std::io::{Error, Result};
use std::ptr;
use winapi::shared::minwindef::{DWORD, FALSE, LPVOID};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Module32First, Module32Next, MODULEENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32};
use winapi::um::winnt::{HANDLE, MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PROCESS_ALL_ACCESS};
use winapi::um::winbase::INFINITE;

pub trait ProcessManager {
	fn open_process(pid: DWORD) -> Result<HANDLE>;
	fn allocate_memory(proc_handle: HANDLE, dll_path: &CString) -> Result<LPVOID>;
	fn write_memory(proc_handle: HANDLE, remote_mem: LPVOID, dll_path: &CString) -> Result<()>;
	fn get_module_base_address(&self, module_name: &str) -> Result<LPVOID>;
	fn get_remote_function_address(&self, module_name: &str, function_name: &str) -> Result<LPVOID>;
	fn create_remote_thread(&self, remote_mem: LPVOID) -> Result<()>;
}

pub struct RemoteProcess {
	pub handle: HANDLE,
	pub pid: DWORD,
}

impl RemoteProcess {
	pub fn new(pid: DWORD) -> Result<Self> {
		let handle = Self::open_process(pid)?;
		Ok(Self { handle, pid })
	}
}

impl Drop for RemoteProcess {
	fn drop(&mut self) {
		unsafe {
			CloseHandle(self.handle);
		}
	}
}

impl ProcessManager for RemoteProcess {
	fn open_process(pid: DWORD) -> Result<HANDLE> {
		let proc_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid) };
		if proc_handle.is_null() || proc_handle == INVALID_HANDLE_VALUE {
			let err = Error::last_os_error();
			eprintln!("[-] OpenProcess failed: {}", err);
			Err(err)
		} else {
			println!("[+] OpenProcess succeeded. Handle: {:?}", proc_handle);
			Ok(proc_handle)
		}
	}

	fn allocate_memory(proc_handle: HANDLE, dll_path: &CString) -> Result<LPVOID> {
		let mem_size = dll_path.to_bytes_with_nul().len();
		let remote_mem = unsafe {
			VirtualAllocEx(
				proc_handle,
				ptr::null_mut(),
				mem_size,
				MEM_COMMIT | MEM_RESERVE,
				PAGE_READWRITE,
			)
		};
		if remote_mem.is_null() {
			Err(Error::last_os_error())
		} else {
			Ok(remote_mem)
		}
	}

	fn write_memory(proc_handle: HANDLE, remote_mem: LPVOID, dll_path: &CString) -> Result<()> {
		let write_result = unsafe {
			WriteProcessMemory(
				proc_handle,
				remote_mem,
				dll_path.as_ptr() as *const _,
				dll_path.to_bytes_with_nul().len(),
				ptr::null_mut(),
			)
		};
		if write_result == 0 {
			Err(Error::last_os_error())
		} else {
			Ok(())
		}
	}

	fn get_module_base_address(&self, module_name: &str) -> Result<LPVOID> {
		unsafe {
			let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid);
			if snapshot == INVALID_HANDLE_VALUE {
				return Err(Error::last_os_error());
			}

			let mut module_entry: MODULEENTRY32 = std::mem::zeroed();
			module_entry.dwSize = std::mem::size_of::<MODULEENTRY32>() as u32;

			if Module32First(snapshot, &mut module_entry) == FALSE {
				CloseHandle(snapshot);
				return Err(Error::last_os_error());
			}

			loop {
				let sz_module = CStr::from_ptr(module_entry.szModule.as_ptr());
				let module_name_cstr = CString::new(module_name)?;

				if sz_module.to_bytes().eq_ignore_ascii_case(module_name_cstr.as_bytes()) {
					CloseHandle(snapshot);
					return Ok(module_entry.modBaseAddr as LPVOID);
				}

				if Module32Next(snapshot, &mut module_entry) == FALSE {
					break;
				}
			}

			CloseHandle(snapshot);
			Err(Error::new(std::io::ErrorKind::NotFound, "Module not found"))
		}
	}

	fn get_remote_function_address(&self, module_name: &str, function_name: &str) -> Result<LPVOID> {
		let local_module_handle = unsafe { GetModuleHandleA(CString::new(module_name)?.as_ptr()) };
		if local_module_handle.is_null() {
			return Err(Error::last_os_error());
		}

		let local_function_address = unsafe {
			GetProcAddress(local_module_handle, CString::new(function_name)?.as_ptr())
		};
		if local_function_address.is_null() {
			return Err(Error::last_os_error());
		}

		let local_module_base = local_module_handle as usize;
		let local_function_offset = (local_function_address as usize) - local_module_base;

		let remote_module_base = self.get_module_base_address(module_name)? as usize;

		let remote_function_address = (remote_module_base + local_function_offset) as LPVOID;

		Ok(remote_function_address)
	}

	fn create_remote_thread(&self, remote_mem: LPVOID) -> Result<()> {
		unsafe {
			let remote_loadlibrarya = self.get_remote_function_address("kernel32.dll", "LoadLibraryA")?;
			if remote_loadlibrarya.is_null() {
				return Err(Error::new(
					std::io::ErrorKind::Other,
					"Failed to get remote LoadLibraryA address",
				));
			}

			let h_thread = CreateRemoteThread(
				self.handle,
				ptr::null_mut(),
				0,
				Some(std::mem::transmute(remote_loadlibrarya)),
				remote_mem,
				0,
				ptr::null_mut(),
			);

			if h_thread.is_null() {
				let error = Error::last_os_error();
				eprintln!("[-] CreateRemoteThread failed: {}", error);
				return Err(error);
			}

			WaitForSingleObject(h_thread, INFINITE);

			CloseHandle(h_thread);

			Ok(())
		}
	}

}
