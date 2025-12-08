import socket
import time
import urllib.request
import urllib.parse
import random
import sys

def log(msg):
    print(f"[SIMULATOR] {msg}")

def simulate_http():
    log("Simulating HTTP traffic...")
    base_url = "http://localhost:8080"
    endpoints = [
        "/",
        "/wp-login.php",
        "/admin",
        "/phpmyadmin",
        "/config.php"
    ]

    # GET requests
    for endpoint in endpoints:
        try:
            url = f"{base_url}{endpoint}"
            with urllib.request.urlopen(url) as response:
                pass
        except Exception:
            pass

    # POST request (Credential harvesting)
    try:
        data = urllib.parse.urlencode({
            'log': f'admin_{random.randint(1, 100)}',
            'pwd': 'password123',
            'wp-submit': 'Log In'
        }).encode()
        req = urllib.request.Request(f"{base_url}/wp-login.php", data=data)
        with urllib.request.urlopen(req) as response:
            pass
        log("  -> Sent HTTP POST login attempt")
    except Exception as e:
        log(f"  -> HTTP POST failed: {e}")

def simulate_ssh():
    log("Simulating SSH traffic...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('localhost', 2222))
        # Receive banner
        s.recv(1024)
        # Send fake version string
        s.send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
        time.sleep(0.5)
        s.close()
        log("  -> Sent SSH connection attempt")
    except Exception as e:
        log(f"  -> SSH failed: {e}")

def simulate_ftp():
    log("Simulating FTP traffic...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('localhost', 2121))
        # Receive banner
        s.recv(1024)
        # Send USER
        s.send(b"USER anonymous\r\n")
        s.recv(1024)
        # Send PASS
        s.send(b"PASS test@test.com\r\n")
        s.recv(1024)
        s.close()
        log("  -> Sent FTP login attempt")
    except Exception as e:
        log(f"  -> FTP failed: {e}")

def main():
    print("🚀 Starting Traffic Simulator for TenebriNET")
    print("Press Ctrl+C to stop")

    try:
        while True:
            simulate_http()
            simulate_ssh()
            simulate_ftp()

            sleep_time = random.uniform(2, 5)
            log(f"Sleeping for {sleep_time:.1f}s...")
            time.sleep(sleep_time)

    except KeyboardInterrupt:
        print("\n👋 Simulation stopped")

if __name__ == "__main__":
    main()
