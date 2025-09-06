# plugins/intell/phishing_guard/tls_probe.py
import ssl, socket

def tls_features(host: str, port: int = 443) -> dict:
    res = {"cert_mismatch": False}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                names = []
                for t,v in cert.get("subject", []):
                    for k,val in v:
                        if k.lower()=="commonName": names.append(val.lower())
                for t,v in cert.get("subjectAltName", []):
                    if t=="DNS": names.append(v.lower())
                res["cert_mismatch"] = names and all(host.lower() not in n and n not in host.lower() for n in names)
    except Exception:
        res["cert_mismatch"] = True  # fail-closed-ish for risk
    return res
