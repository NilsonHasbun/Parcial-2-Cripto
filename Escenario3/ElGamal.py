import os
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def generate_elgamal_keys():

    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()
    
    # Serializamos la clave pública en formato uncompressed (X9.62)
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    # Extraemos el valor entero de la clave privada y lo convertimos a hexadecimal
    private_num = private_key.private_numbers().private_value
    private_hex = format(private_num, 'x')
    
    return {
        "publicKey": public_bytes.hex(),
        "privateKey": private_hex,
        "keyPair": (private_key, public_key)
    }


def encrypt_elgamal(message: str, receiver_public_key: str):

    # Convertir la clave pública del receptor de hex a objeto de clave EC
    receiver_public_bytes = bytes.fromhex(receiver_public_key)
    receiver_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), receiver_public_bytes)
    
    # Generar clave efímera
    ephemeral_private = ec.generate_private_key(ec.SECP256K1(), default_backend())
    ephemeral_public = ephemeral_private.public_key()
    
    # Derivar el secreto compartido mediante ECDH
    shared_secret = ephemeral_private.exchange(ec.ECDH(), receiver_public)
    
    # Derivar la clave simétrica AES-192: SHA-256 y tomar los primeros 24 bytes
    hash_shared = hashlib.sha256(shared_secret).digest()
    key = hash_shared[:24]
    
    # Generar un IV aleatorio de 16 bytes
    iv = os.urandom(16)
    
    # Cifrado AES-192-CBC con PKCS7 padding
    cipher = AES.new(key, AES.MODE_CBC, iv)
    message_bytes = message.encode('utf-8')
    padded_message = pad(message_bytes, AES.block_size)
    ciphertext = cipher.encrypt(padded_message)
    
    # Serializar la clave pública efímera (en formato sin comprimir, X9.62)
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
   
    # Reconstruir la clave privada del receptor
    private_value = int(private_key_hex, 16)
    recipient_private_key = ec.derive_private_key(private_value, ec.SECP256K1(), default_backend())
    
    # Reconstruir la clave pública efímera
    ephemeral_public_bytes = bytes.fromhex(ephemeral_public_key_hex)
    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), ephemeral_public_bytes)
    
    # Derivar el secreto compartido mediante ECDH
    shared_secret = recipient_private_key.exchange(ec.ECDH(), ephemeral_public)
    
    # Derivar la clave simétrica AES-192
    hash_shared = hashlib.sha256(shared_secret).digest()
    key = hash_shared[:24]
    
    # Decodificar IV y mensaje cifrado
    iv = base64.b64decode(iv_base64)
    ciphertext = base64.b64decode(ciphertext_base64)
    
    # Descifrado AES-192-CBC
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = cipher.decrypt(ciphertext)
    message_bytes = unpad(padded_message, AES.block_size)
    
    return message_bytes.decode('utf-8')


# Ejemplo de uso
if __name__ == '__main__':
    print("=== Generación de claves (ElGamal/ECIES) ===")
    keys = generate_elgamal_keys()
    receiver_pub = keys["publicKey"]
    receiver_priv = keys["privateKey"]
    print("Clave pública receptor:", receiver_pub)
    print("Clave privada receptor:", receiver_priv)
    
    mensaje = "Mensaje secreto mediante ECIES simulado con Python"
    print("\n-- Cifrado --")
    encrypted = encrypt_elgamal(mensaje, receiver_pub)
    print("Mensaje cifrado (base64):", encrypted["ciphertext"])
    print("IV (base64):", encrypted["iv"])
    print("Clave pública efímera:", encrypted["ephemeralPublicKey"])
    
    print("\n-- Descifrado --")
    decrypted = decrypt_elgamal(encrypted["ciphertext"], encrypted["iv"], encrypted["ephemeralPublicKey"], receiver_priv)
    print("Mensaje descifrado:", decrypted)
