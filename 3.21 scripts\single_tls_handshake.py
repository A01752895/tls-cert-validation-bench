import argparse
import socket
import ssl
from pathlib import Path

def make_context_verify(root_pem: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(root_pem))
    return ctx

def make_context_noverify() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--mode", choices=["verify", "noverify"], required=True)
    parser.add_argument("--cafile", default=None)
    args = parser.parse_args()

    if args.mode == "verify":
        if not args.cafile:
            raise ValueError("--cafile es obligatorio en modo verify")
        ctx = make_context_verify(Path(args.cafile))
    else:
        ctx = make_context_noverify()

    with socket.create_connection((args.host, args.port), timeout=3) as sock:
        with ctx.wrap_socket(sock, server_hostname="localhost", do_handshake_on_connect=True) as ssock:
            print("Handshake OK")
            print("Cipher:", ssock.cipher())

if __name__ == "__main__":
    main()
