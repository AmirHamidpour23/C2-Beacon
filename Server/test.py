# test_send.py
import socket
import time
from encrypt import EncryptedCommunicator

def send_test_command():
    """Send a command directly to test"""
    sock = socket.socket()
    sock.connect(('127.0.0.1', 8080))
    
    encryptor = EncryptedCommunicator("Mr.Robot")
    
    # Send command
    command = {
        "type": "command",
        "command": "whoami",
        "timestamp": time.time()
    }
    
    print(f"Sending: {command}")
    encrypted = encryptor.EncryptMessage(command)
    sock.send(encrypted)
    
    # Get response
    response = sock.recv(4096)
    decrypted = encryptor.DecryptMessage(response)
    print(f"Response: {decrypted}")
    
    sock.close()

if __name__ == "__main__":
    send_test_command()