import os
import base64
import binascii
import hashlib
import hmac
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def generate_rsa_key_pair():
    """Generate a new RSA key pair (private and public key)."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_aes_key(aes_key, public_key):
    """Encrypt an AES key using RSA public key."""
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return base64.b64encode(encrypted_key).decode('utf-8')

def decrypt_aes_key(encrypted_key_b64, private_key):
    """Decrypt an AES key using RSA private key."""
    encrypted_key = base64.b64decode(encrypted_key_b64)
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    return cipher_rsa.decrypt(encrypted_key)

def encrypt_message(message, aes_key):
    """Encrypt a message using AES-256-CBC.
    
    Args:
        message: The message to encrypt (str or bytes)
        aes_key: The AES key to use for encryption (bytes)
    """
    # Ensure message is in bytes
    if isinstance(message, str):
        message = message.encode('utf-8')
    elif not isinstance(message, bytes):
        raise ValueError("Message must be either str or bytes")
    
    # Generate a random IV (Initialization Vector)
    iv = get_random_bytes(16)
    
    # Create AES cipher
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    
    # Pad the message and encrypt
    padded_message = pad(message, AES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    
    # Return IV + ciphertext as base64
    encrypted_data = iv + ciphertext
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_message(encrypted_message_b64, aes_key):
    """Decrypt a message using AES-256-CBC."""
    # Decode from base64
    encrypted_data = base64.b64decode(encrypted_message_b64)
    
    # Extract IV and ciphertext
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # Create AES cipher and decrypt
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_message = cipher.decrypt(ciphertext)
    
    # Unpad and return the original message
    return unpad(padded_message, AES.block_size).decode('utf-8')

def generate_aes_key():
    """Generate a random 32-byte AES key."""
    return get_random_bytes(32)  # 256 bits

def hash_password(password):
    """Hash a password for storing."""
    if not password:
        raise ValueError("Password cannot be empty")
    
    # Generate a random salt
    salt = get_random_bytes(32)
    
    # Use PBKDF2 with 100,000 iterations
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000,  # Number of iterations
        dklen=32  # Length of the derived key
    )
    
    # Combine salt and key with a separator that won't appear in base64
    combined = salt + key
    
    # Encode to base64 for storage
    return base64.b64encode(combined).decode('utf-8')

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user."""
    if not stored_password or not provided_password:
        return False
        
    try:
        # Decode the stored password
        decoded = base64.b64decode(stored_password)
        
        # Extract salt and key
        salt = decoded[:32]
        stored_key = decoded[32:64]  # First 32 bytes after salt
        
        # Generate the key from the provided password
        new_key = hashlib.pbkdf2_hmac(
            'sha256',
            provided_password.encode('utf-8'),
            salt,
            100000,
            dklen=32
        )
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(stored_key, new_key)
        
    except (ValueError, binascii.Error) as e:
        print(f"Error verifying password: {str(e)}")
        return False
