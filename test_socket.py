#!/usr/bin/env python3
import socket
import sys

def exploit(target_ip: str, target_port: int) -> dict:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((target_ip, target_port))
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return {"success": True, "message": f"Connected! Banner: {banner[:50]}", "evidence": banner}
    except Exception as e:
        return {"success": False, "message": f"Error: {e}", "evidence": str(e)}

if __name__ == '__main__':
    result = exploit('192.168.126.128', 22)
    print(result)
