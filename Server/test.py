import socket
from encrypt import EncryptedCommunicator

# Connect to our C2 server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 8080))

# Use same password as server
encryptor = EncryptedCommunicator('Mr.Robot')

# Send a test message
test_data = {"beacon_id": "test_beacon", "status": "checking_in"}
encrypted = encryptor.EncryptMessage(test_data)
client_socket.send(encrypted)

# Get response
response = client_socket.recv(4096)
decrypted = encryptor.DecryptMessage(response)
print("Server response:", decrypted)

client_socket.close()