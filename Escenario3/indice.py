import os
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding, ec
from cryptography.hazmat.backends import default_backend

# ==================== Funciones RSA-OAEP ====================
def generate_rsa_keys():
 
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return public_key_pem, private_key_pem

def encrypt_rsa(message: str, public_key_pem: str) -> bytes:

    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_rsa(ciphertext: bytes, private_key_pem: str) -> str:

    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None
    )
    plaintext = private_key.decrypt(
        ciphertext,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')

#Funciones ECIES (ElGamal simulado)
def generate_elgamal_keys():

    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()
    
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    private_num = private_key.private_numbers().private_value
    private_hex = format(private_num, 'x')
    
    return {
        "publicKey": public_bytes.hex(),
        "privateKey": private_hex,
        "keyPair": (private_key, public_key)
    }

def encrypt_elgamal(message: str, receiver_public_key: str):
 
    # Convertir la clave pública del receptor desde hexadecimal
    receiver_public_bytes = bytes.fromhex(receiver_public_key)
    receiver_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), receiver_public_bytes)
    
    # Generar clave efímera
    ephemeral_private = ec.generate_private_key(ec.SECP256K1(), default_backend())
    ephemeral_public = ephemeral_private.public_key()
    
    # Derivar secreto compartido vía ECDH
    shared_secret = ephemeral_private.exchange(ec.ECDH(), receiver_public)
    
    # Derivar clave simétrica AES-192: SHA-256 sobre secret y tomar los primeros 24 bytes
    hash_shared = hashlib.sha256(shared_secret).digest()
    key = hash_shared[:24]
    
    # Generar un IV aleatorio de 16 bytes
    iv = os.urandom(16)
    
    # Cifrado AES-192-CBC con padding PKCS7
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message_bytes = message.encode('utf-8')
    padded_message = pad(message_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    
    ephemeral_public_bytes = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    return {
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
        "iv": base64.b64encode(iv).decode('utf-8'),
        "ephemeralPublicKey": ephemeral_public_bytes.hex()
    }

def decrypt_elgamal(ciphertext_base64: str, iv_base64: str, ephemeral_public_key_hex: str, private_key_hex: str):
 
    private_value = int(private_key_hex, 16)
    recipient_private_key = ec.derive_private_key(private_value, ec.SECP256K1(), default_backend())
    
    ephemeral_public_bytes = bytes.fromhex(ephemeral_public_key_hex)
    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), ephemeral_public_bytes)
    
    shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public)
    
    hash_shared = hashlib.sha256(shared_secret).digest()
    key = hash_shared[:24]
    
    iv = base64.b64decode(iv_base64)
    ciphertext = base64.b64decode(ciphertext_base64)
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = cipher.decrypt(ciphertext)
    message_bytes = unpad(padded_message, AES.block_size)
    return message_bytes.decode('utf-8')


#Ejecución de la integración 
if __name__ == '__main__':
    # Ejemplo RSA-OAEP
    print("=== RSA-OAEP ===")
    public_key, private_key = generate_rsa_keys()
    mensaje = "Hola, soy RSA"
    cifrado = encrypt_rsa(mensaje, public_key)
    descifrado = decrypt_rsa(cifrado, private_key)
    
    print("Enviado:", mensaje)
    print("Cifrado (base64):", base64.b64encode(cifrado).decode('utf-8'))
    print("Descifrado:", descifrado)
    print()
    
    # Ejemplo ECIES (ElGamal simulado)
    print("=== ECIES (ElGamal simulado) ===")
    receiver = generate_elgamal_keys()
    mensaje2 = "Hola desde ElGamal"
    encrypted_data = encrypt_elgamal(mensaje2, receiver["publicKey"])
    descifrado2 = decrypt_elgamal(
        encrypted_data["ciphertext"],
        encrypted_data["iv"],
        encrypted_data["ephemeralPublicKey"],
        receiver["privateKey"]
    )
    
    print("Enviado:", mensaje2)
    print("Cifrado (base64):", encrypted_data["ciphertext"])
    print("Descifrado:", descifrado2)
