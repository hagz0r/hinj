# hinj 

## Overview

This project implements a robust **Dynamic Link Library (DLL) Injector** using the **Rust** programming language, designed to inject a DLL into the address space of a running Windows process. It leverages key Windows APIs such as `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` to facilitate the injection process. The injector ensures compatibility with processes by addressing critical challenges such as **Address Space Layout Randomization (ASLR)** and thread synchronization.

The primary use case for this injector is testing and instrumentation of software, allowing you to load external code into processes for debugging, monitoring, or extending functionality. This injector is built with an emphasis on performance, memory safety, and system-level integrity.

---
## Features

- **ASLR-aware Injection**: Dynamically calculates the correct address of `LoadLibraryA` in the target process, ensuring compatibility with modern systems using Address Space Layout Randomization.
- **Remote Thread Execution**: Injects the specified DLL into the target process by creating a remote thread that executes `LoadLibraryA` to load the DLL.
- **Memory Allocation in Remote Process**: Allocates memory in the target process and writes the DLL path into it using `VirtualAllocEx` and `WriteProcessMemory`.
- **Thread Synchronization**: Waits for the injected remote thread to finish execution, ensuring that the DLL has been properly loaded.

---
## Prerequisites

- **Operating System**: Windows 10 or later (for compatibility with ASLR and 64-bit systems).
- **Rust Toolchain**: Ensure the latest version of Rust is installed. You can install Rust from [here](https://www.rust-lang.org/tools/install).
- **Target Architecture**: The architecture of the injector and the target process must match (e.g., 64-bit injector for 64-bit processes).

---
## Installation

1. Clone the repository:
2. Build the project:

   ```sh
   cargo build --release
   ```

3. Ensure the target DLL is built with the same architecture as the target process (either 32-bit or 64-bit). You can compile a DLL in Rust with:

   ```sh
   cargo build --target x86_64-pc-windows-msvc --release
   ```
---

## Usage

### Command-line Execution

To use the injector, simply run the compiled binary from the command line, passing in the name of the target process and the path to the DLL you want to inject.

```sh
hinj.exe <process_name> <dll_path>
```

**Example**:

```sh
hinj.exe Bodycam-Win64-Shipping.exe C:\path\to\your\dll\bodycam.dll
```

---

## Common Issues and Troubleshooting

1. **ASLR Incompatibility**: If the injection fails due to ASLR, ensure the injector is calculating the address of `LoadLibraryA` in the remote process by obtaining the correct base address of `kernel32.dll`.

2. **Insufficient Permissions**: Ensure that the injector is being run with administrative privileges. Some processes, especially system or protected processes, may require elevated privileges to inject a DLL.

3. **Architecture Mismatch**: The architecture of the DLL, injector, and target process must match. For example, if the target process is 64-bit, both the injector and the DLL must be 64-bit.

4. **Security Software Interference**: Anti-virus or other security software may block DLL injection as it is often used by malware. For testing purposes, temporarily disable security software in a controlled environment to ensure the injection is not being blocked.

---

## Future Enhancements

- **Code Injection (Shellcode)**: In addition to DLL injection, the project can be extended to inject arbitrary shellcode into the target process for advanced use cases such as reverse engineering and dynamic analysis.
- **Cross-architecture Injection**: Implement support for injecting a 32-bit DLL into a 64-bit process and vice versa.
- **Thread Hijacking**: Explore more sophisticated injection techniques like thread hijacking, where a running thread in the target process is paused, its execution context modified to load a DLL, and then resumed.
---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
