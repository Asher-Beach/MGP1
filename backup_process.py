import socket
from datetime import datetime

import critical_service

BACKUP_PORT = 50001
ALERT_DATAGRAM = "YourCoworkerIsDead"

def wait_for_failover():
    # Backup sits waiting for the monitor's failover signal on BACKUP_PORT
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
        server_socket.settimeout(60.0)
        server_socket.bind((critical_service.HOST, BACKUP_PORT))
        try:
            while True:
                data, address = server_socket.recvfrom(1024)
                datagram = data.decode("utf-8")
                if datagram == ALERT_DATAGRAM:
                    # Failover signal received
                    critical_service.load_state()
                    return True
        except socket.timeout:
            return False

def main():
    # Once the monitor signals failover, run identically to the primary
    if wait_for_failover():
        critical_service.load_state()
        print(f"[Service Restored] backup assumed control at {datetime.now()}")
        print(f"\nState restored:\n\tValid Attempts: {critical_service.valid_attempts}\n\tInvalid Attempts: {critical_service.invalid_attempts}")
        print(f"\n--- Resuming Service ---\n")
        critical_service.main()

if __name__ == "__main__":
    main()
