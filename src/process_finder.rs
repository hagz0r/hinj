use winapi::um::tlhelp32::*;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::shared::minwindef::{DWORD, FALSE};
use winapi::um::winnt::HANDLE;

pub fn get_pid_of_process(process_name: &str) -> Option<DWORD> {
	unsafe {
		let snapshot: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if snapshot == INVALID_HANDLE_VALUE {
			println!("[-] Failed to get process snapshot");
			return None;
		}

		let mut process_entry: PROCESSENTRY32W = std::mem::zeroed();
		process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

		if Process32FirstW(snapshot, &mut process_entry) == FALSE {
			CloseHandle(snapshot);
			println!("[-] Failed to get first process");
			return None;
		}

		loop {
			let exe_file = String::from_utf16_lossy(&process_entry.szExeFile);
			if exe_file.trim_end_matches('\u{0}').eq_ignore_ascii_case(process_name) {
				let pid = process_entry.th32ProcessID;
				CloseHandle(snapshot);
				return Some(pid);
			}

			if Process32NextW(snapshot, &mut process_entry) == FALSE {
				break;
			}
		}

		CloseHandle(snapshot);
		println!("[-] Process not found with name: {:?}", process_name);
		None
	}
}
