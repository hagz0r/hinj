use std::ffi::CString;
use crate::injector::DllInjector;
use crate::process_finder::get_pid_of_process;
use crate::process_manager::{ RemoteProcess};

mod injector;
mod process_manager;
mod process_finder;

fn main() {
	let args = std::env::args().collect::<Vec<_>>();
	if args.len() < 3 {
		eprintln!("Usage: {} <process name> <DLL path>", args[0]);
		std::process::exit(1);
	}

	let pid = get_pid_of_process(args[1].as_str())
		.expect("[-] Failed to get PID of process");

	let remote_process = RemoteProcess::new(pid)
		.expect("[-] Failed to open process");

	let dll_path = args[2].clone();

	DllInjector::new(&dll_path)
		.inject(&remote_process)
		.expect("[-] Failed to inject DLL");

	println!("[+] Injected!");
}
