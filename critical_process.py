import os
import random
import socket
import threading

HOST = "127.0.0.1"
PORT = 50000
HEARTBEAT_INTERVAL = 5           # T: ms between heartbeat sends
HEARTBEAT_PAYLOAD = "SoSecret"   # must match monitor's DESIRED_DATAGRAM
CRASH_PROBABILITY = 0.01         # % chance of failure state

def terminate(reason):
    # Hard-exit the process immediately
    print(f"[critical] crash injected: {reason}")
    os._exit(1)

def maybe_crash(reason = "random fault"):
    # Non-deterministic crash trigger on incoming requests
    if random.random() < CRASH_PROBABILITY:
        terminate(reason)

def send_heartbeats(stop_event):
    # Push heartbeat to the monitor every HEARTBEAT_INTERVAL ms
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socket:
        destination = (HOST, PORT)
        while not stop_event.is_set():
            socket.sendto(HEARTBEAT_PAYLOAD.encode("utf-8"), destination)
            stop_event.wait(HEARTBEAT_INTERVAL / 1000.0)

def main():
    # Run the critical service
    stop_event = threading.Event()
    threading.Thread(target=send_heartbeats, args=(stop_event,), daemon=True).start()

    # Service loop: inspect incoming requests, then inject a crash
    while True:
        # Receive and validate incoming requests
        maybe_crash()

main()
