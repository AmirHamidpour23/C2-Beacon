import json 
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes 
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptedCommunicator:
    def __init__(self, password: str):
        #kdf is getting used here as a password strengthener 
        #the password is later on going to get used as the encryption end decryption key
        kdf = PBKDF2HMAC(  
          algorithm=hashes.SHA256(),
          length=32, #the 32 bytes length (256 bits) is for AES-256 but the crypto library will only take the first 16 bytes
          salt=b'the_salt', #random salt for added security
          iterations=100000, #something to stop brute-forceing
                              #it's just saying how many times we are doing the scrambling process 
        )

        #this is where the password becomes the key for the fernet AES-128 encryption
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self.cipher_suite = Fernet(key)

#essentially up until here the process is, password -> key, the process the key goes through is:
    #key "TheKey123" -> bytes -> sha256 & salt x100000 -> base64 encoded -> saved as key for AES-128

    def EncryptMessage(self, data: dict): 
    #this function is encrypting the message from a python dict -> json -> bytes -> AES
        JsonData = json.dumps(data).encode() #dictionary -> Json string -> bytes
        encrypted_data = self.cipher_suite.encrypt(JsonData) # bytes -> Fernet which is AES-128-CBC

        return encrypted_data

    def DecryptMessage(self, encrypted_data: bytes):
        #this fuction is taking the AES-128 encrypted bytes that we got from "EncryptMessage"
        #and turns them back to python dict. Pretty much the reverse of EncryptMessage

        decrypted_bytes = self.cipher_suite.decrypt(encrypted_data) # AES encrypted bytes -> bytes

        decrypted_data = json.loads(decrypted_bytes.decode()) # bytes -> json string -> python dict

        return decrypted_data
    
def test():
    print('testing encryption')

    com = EncryptedCommunicator("Mr.robot")

    command = {
        "command": "get_sys_info",
        "task_id": "12345",
        "arg": []
    }

    print("original command:  {command}")

    encrypted = com.EncryptMessage(command)
    print(f"encrypted data: {encrypted}")
    print (f"length: {len(encrypted)} in bytes")

    decrypted = com.DecryptMessage(encrypted)
    print(f"encrypted data: {decrypted}")

    if command == decrypted:
        print ("SUCESS YOU BASTARD")

    else:
        print("FAILURE KYS")

        return command == decrypted
        
if __name__ == "__main__":
    test()