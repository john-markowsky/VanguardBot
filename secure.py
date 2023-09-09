from cryptography.fernet import Fernet

def encrypt_data(data: str, key: bytes) -> str:
    cipher = Fernet(key)
    encrypted_data = cipher.encrypt(data.encode())
    return encrypted_data.decode()

def decrypt_data(encrypted_data: str, key: bytes) -> str:
    cipher = Fernet(key)
    decrypted_data = cipher.decrypt(encrypted_data.encode())
    return decrypted_data.decode()
