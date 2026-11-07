#!/usr/bin/env python3
"""
TryHackMe - Scripting (Task 2: [Medium] Gotta Catch 'em All)
Connects to dynamic web servers on changing ports, parses mathematical operations,
updates a running total starting at 0, and hops to the next port until reaching port 9765 (STOP).

Usage:
  python3 solve_task2.py [target_ip]
"""

import socket
import sys
import time
import re

DEFAULT_IP = "10.145.149.142"
START_PORT = 1337
END_PORT = 9765

def fetch_port(ip: str, port: int, timeout: float = 1.5) -> str:
    """Sends HTTP GET request to target port and retrieves full response."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.sendall(f"GET / HTTP/1.0\r\nHost: {ip}:{port}\r\n\r\n".encode())
        res = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            res += chunk
        s.close()
        return res.decode("utf-8", errors="ignore")
    except Exception:
        s.close()
        return ""

def solve(ip: str) -> float:
    print(f"[*] Target IP: {ip}")
    print(f"[*] Waiting for sequence to cycle to starting port {START_PORT}...")

    current_port = START_PORT
    total = 0.0

    # Wait for port 1337 to open
    retries = 0
    resp = ""
    while True:
        resp = fetch_port(ip, current_port)
        if resp and "HTTP/" in resp:
            break
        retries += 1
        if retries % 20 == 0:
            print(f"[*] Waiting for port {START_PORT}... ({retries * 0.1:.1f}s elapsed)")
        time.sleep(0.1)

    print(f"[+] Connected to initial port {current_port}!")

    step = 0
    while True:
        step += 1
        if not resp:
            # Retry fetching from current_port up to 4s (40-50 retries)
            for _ in range(50):
                resp = fetch_port(ip, current_port)
                if resp and "HTTP/" in resp:
                    break
                time.sleep(0.08)

        if not resp:
            print(f"[-] Timed out waiting for port {current_port}")
            break

        body = resp.split("\r\n\r\n")[-1].strip()
        print(f"[Step {step:02d}] Port {current_port}: {body}")

        if "STOP" in body or current_port == END_PORT:
            print(f"[+] Reached STOP condition at port {current_port}!")
            break

        m = re.search(r"(add|minus|multiply|divide)\s+([\d\.\-]+)\s+(\d+)", body, re.IGNORECASE)
        if not m:
            print(f"[-] Could not parse operation in body: '{body}'")
            break

        op, val, next_port = m.group(1).lower(), float(m.group(2)), int(m.group(3))

        prev_total = total
        if op == "add":
            total += val
        elif op == "minus":
            total -= val
        elif op == "multiply":
            total *= val
        elif op == "divide":
            total /= val

        print(f"       Calc: {prev_total:.4f} {op} {val} = {total:.4f} -> Next: {next_port}")

        current_port = next_port
        resp = ""

        # Fetch final response if next port is END_PORT
        if current_port == END_PORT:
            for _ in range(50):
                resp = fetch_port(ip, current_port)
                if resp and "HTTP/" in resp:
                    final_body = resp.split("\r\n\r\n")[-1].strip()
                    print(f"[Final] Port {current_port}: {final_body}")
                    break
                time.sleep(0.08)
            break

    return total

def main():
    target_ip = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_IP
    final_number = solve(target_ip)
    print("=" * 55)
    print(f"[*] Final raw number: {final_number}")
    print(f"[+] Final Answer (rounded to 2 decimal places): {round(final_number, 2):.2f}")
    print("=" * 55)

if __name__ == "__main__":
    main()
