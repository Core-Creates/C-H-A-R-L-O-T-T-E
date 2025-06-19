def run_plugin(targets=None, output_dir="data/findings"):
    os.makedirs(output_dir, exist_ok=True)
    for host in targets:
        try:
            conn = socket.create_connection((host, 80), timeout=3)
            conn.sendall(b"HEAD / HTTP/1.1\r\nHost: %b\r\n\r\n" % host.encode())
            banner = conn.recv(1024).decode()
            output_path = os.path.join(output_dir, f"http_banner_{host}.txt")
            with open(output_path, "w") as f:
                f.write(banner)
            print(f"[HTTP] Banner for {host} saved to {output_path}")
            conn.close()
        except Exception as e:
            print(f"[!] Banner grab failed for {host}: {e}")
#     print(f"[HTTP] Completed banner grabs for {len(targets)} hosts.")
#     print(f"[HTTP] Results saved to {output_dir}")