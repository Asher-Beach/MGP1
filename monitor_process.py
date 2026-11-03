import socket
import time
from datetime import datetime

HOST = "127.0.0.1"
PORT = 50000
BACKUP_PORT = 50001
TIMEOUT = 10.0
DESIRED_DATAGRAM = "SoSecret"
ALERT_DATAGRAM = "YourCoworkerIsDead"
current_client = "Primary"
client_isAlive = True
known_threats = []


def incidentHandler(incident):
    print(f"Incident occured at {datetime.now()}.")
    with open("log.txt", "a", encoding="utf-8") as file:
        file.write(f"Security incident {incident} occured at {datetime.now()}\n")
        file.close()

def crashHandler(server_socket):
    global current_client, client_isAlive
    if(current_client == "Primary"):
        print(f"[Failover Triggered] {datetime.now()} -- promoting backup node; sending failover signal to {HOST}:{BACKUP_PORT}.")
        server_socket.sendto(ALERT_DATAGRAM.encode("utf-8"), (HOST, BACKUP_PORT))
        current_client = "Backup"
    elif(current_client == "Backup"):
        print(f"[Backup Failed] {datetime.now()} -- backup node is also down; no standby remaining.")
        current_client = "None"
        client_isAlive = False
    


with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_socket:
    server_socket.settimeout(TIMEOUT)
    server_socket.bind((HOST, PORT))
    while True:
        try:
            if(client_isAlive):
                print("Checking to verify the service is still alive...")
            else:
                print("Checking to see if the service has come back online...")
            
            data, address = server_socket.recvfrom(1024)
            datagram = data.decode('utf-8')
            
            if(datagram != DESIRED_DATAGRAM):
                print(f"That's an attacker (or the service sends the wrong datagram.) Occured at {datetime.now()} from address {address}.")
                known_threats.append(address)
                incidentHandler("Potential Threat Detected")
            
            elif(address in known_threats):
                print(f"This address has been put on the threat list, so its connections are ignored. Occured at {datetime.now()} from address {address}.")
                incidentHandler("Logged potential threat retried connection")
            elif(client_isAlive):
                print("The service is still alive.")
            
            else:
                print("The service has come back to life. Make sure backup node is up.")
                client_isAlive = True
                current_client = "Primary"

        except socket.timeout:
            print(f"[Crash Detected] {datetime.now()} -- {TIMEOUT:.0f}s elapsed with no heartbeat from the {current_client} node.")
            incidentHandler("Timeout Reached")
            crashHandler(server_socket)
            continue
        except OSError:
            print("A buffer overflow occured, handled safely.")
            continue





            
            