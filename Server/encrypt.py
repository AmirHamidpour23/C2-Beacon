import json
import base64

class RC4Cipher:
    """RC4 Encryption/Decryption (same operation for both)"""
    def __init__(self, key: str):
        self.key = key.encode('utf-8')
        self.S = list(range(256))
        self._key_schedule()
    
    def _key_schedule(self):
        """RC4 Key Scheduling Algorithm"""
        j = 0
        key_len = len(self.key)
        for i in range(256):
            j = (j + self.S[i] + self.key[i % key_len]) % 256
            self.S[i], self.S[j] = self.S[j], self.S[i]
    
    def crypt(self, data: bytes) -> bytes:
        """Encrypt or decrypt data (RC4 is symmetrical)"""
        S = self.S.copy()
        i = j = 0
        result = bytearray()
        
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            result.append(byte ^ k)
        
        return bytes(result)

class EncryptedCommunicator:
    def __init__(self, password: str):
        """Initialize with password (used as encryption key)"""
        self.cipher = RC4Cipher(password)
    
    def EncryptMessage(self, data: dict) -> bytes:
        """
        Encrypt a Python dictionary to bytes
        Steps: Dict → JSON → Bytes → RC4 → Base64
        """
        # Convert dict to JSON string, then to bytes
        json_str = json.dumps(data)
        json_bytes = json_str.encode('utf-8')
        
        # Encrypt with RC4
        encrypted = self.cipher.crypt(json_bytes)
        
        # Encode to base64 for safe transmission
        return base64.b64encode(encrypted)
    
    def DecryptMessage(self, encrypted_data: bytes) -> dict:
        """
        Decrypt bytes back to Python dictionary
        Steps: Base64 → RC4 → Bytes → JSON → Dict
        """
        # Decode from base64
        encrypted = base64.b64decode(encrypted_data)
        
        # Decrypt with RC4 (same as encrypt)
        decrypted = self.cipher.crypt(encrypted)
        
        # Convert bytes to string, then parse JSON
        json_str = decrypted.decode('utf-8')
        return json.loads(json_str)

# Test function
if __name__ == "__main__":
    # Test the encryption
    comm = EncryptedCommunicator("Mr.Robot")
    
    test_data = {"command": "whoami", "type": "system"}
    
    print("Testing RC4 Encryption:")
    print(f"Original: {test_data}")
    
    encrypted = comm.EncryptMessage(test_data)
    print(f"Encrypted (base64): {encrypted}")
    
    decrypted = comm.DecryptMessage(encrypted)
    print(f"Decrypted: {decrypted}")
    
    if test_data == decrypted:
        print("✅ Encryption/Decryption successful!")
    else:
        print("❌ Failed!")