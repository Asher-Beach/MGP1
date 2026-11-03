import argparse
import json
import socket
from datetime import datetime


HOST = "127.0.0.1"
CLIENT_PORT = 50002


def stamp():
    return datetime.now().strftime("%H:%M:%S")


def query_once(sock, dest):
    sock.sendto(b"STATUS", dest)
    data, _ = sock.recvfrom(1024)
    return json.loads(data.decode("utf-8"))


def main():
    parser = argparse.ArgumentParser(
        description="Client that polls the resilient security service for its "
                    "current state (targets 127.0.0.1:50002).")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=CLIENT_PORT)
    parser.add_argument("--interval", type=float, default=1.0,
                        help="seconds between queries (default 1.0)")
    parser.add_argument("--count", type=int, default=0,
                        help="number of queries to send; 0 means run forever "
                             "(default 0)")
    parser.add_argument("--timeout", type=float, default=2.0,
                        help="seconds to wait for a response before declaring "
                             "the service unavailable (default 2.0)")
    args = parser.parse_args()

    dest = (args.host, args.port)
    print(f"[client {stamp()}] polling {args.host}:{args.port} every "
          f"{args.interval}s (Ctrl+C to stop)")

    sent = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(args.timeout)
        try:
            while args.count == 0 or sent < args.count:
                try:
                    reply = query_once(sock, dest)
                    print(f"[client {stamp()}] served by {reply['node']:>7} | "
                          f"valid={reply['valid_attempts']} "
                          f"invalid={reply['invalid_attempts']}")
                except socket.timeout:
                    # No node is currently bound to CLIENT_PORT -- e.g. the
                    # primary has crashed and the backup has not taken over yet.
                    print(f"[client {stamp()}] !! no response -- service "
                          f"unavailable (failover in progress?)")
                except (json.JSONDecodeError, KeyError, OSError) as e:
                    print(f"[client {stamp()}] !! malformed response: {e}")
                sent += 1
                # Pace queries, but skip the final sleep so --count exits.
                if args.count == 0 or sent < args.count:
                    _sleep(args.interval)
        except KeyboardInterrupt:
            print(f"\n[client {stamp()}] stopped after {sent} queries.")


def _sleep(seconds):
    import time
    time.sleep(seconds)


if __name__ == "__main__":
    main()
