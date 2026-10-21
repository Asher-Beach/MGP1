import socket

HOST = "127.0.0.1"
PORT = 50000
TIMEOUT = 10.0
DESIRED_DATAGRAM = "SoSecret"
known_threats = []

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.settimeout(TIMEOUT)
    server_socket.bind((HOST, PORT))
    client_isAlive = True
    while True:
        try:
            if(client_isAlive):
                print("Checking to verify the service is still alive...")
            else:
                print("Checking to see if the service has come back online...")
            
            data, address = server_socket.recvfrom(1024)
            datagram = data.decode('utf-8')
            
            if(datagram != DESIRED_DATAGRAM):
                print("That's an attacker (or the service sends the wrong datagram.)")
                known_threats.add(address)
            
            elif(address in known_threats):
                print("This address has been put on the threat list, so its connections are ignored.") 

            elif(client_isAlive):
                print("The service is still alive!")
            
            else:
                print("The service has come back to life!")
                client_isAlive = True

        except socket.timeout:
            print("10 seconds passed without a message! The client must be dead...")
            client_isAlive = False
            continue
        except OSError:
            print("A buffer overflow occured, handled it safely!")
            continue




            
            