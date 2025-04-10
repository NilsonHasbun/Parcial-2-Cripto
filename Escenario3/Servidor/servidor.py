import os
import base64
import hashlib
import time

from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Util.Padding import pad, unpad

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding, ec
from cryptography.hazmat.backends import default_backend

#Funciones ChaCha20
def encrypt_message_chacha20(message: str, key: bytes, nonce: bytes):

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    return {"ciphertext": ciphertext, "tag": tag}

def decrypt_message_chacha20(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes):

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

# ==================== Funciones AES-192 CBC ====================
def encrypt_aes192_cbc(message: str, key: bytes):
 
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(message.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded)
    return {"ciphertext": ciphertext, "iv": iv}

def decrypt_aes192_cbc(ciphertext: bytes, key: bytes, iv: bytes):

    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    plaintext = unpad(padded, AES.block_size)
    return plaintext.decode('utf-8')

# ==================== Funciones RSA-OAEP ====================
def generate_rsa_keys():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return public_pem, private_pem

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

# ==================== Funciones ECIES (ElGamal simulado) ====================
def generate_elgamal_keys():

    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()

    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    private_num = private_key.private_numbers().private_value
    private_hex = format(private_num, 'x')
    return {"publicKey": public_bytes.hex(), "privateKey": private_hex, "keyPair": (private_key, public_key)}

def encrypt_elgamal(message: str, receiver_public_key: str):
  
    receiver_public_bytes = bytes.fromhex(receiver_public_key)
    receiver_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), receiver_public_bytes)

    # Clave efímera
    ephemeral_private = ec.generate_private_key(ec.SECP256K1(), default_backend())
    ephemeral_public = ephemeral_private.public_key()

    shared_secret = ephemeral_private.exchange(ec.ECDH(), receiver_public)
    key = hashlib.sha256(shared_secret).digest()[:24]

    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = pad(message.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded)

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
    recipient_private = ec.derive_private_key(private_value, ec.SECP256K1(), default_backend())

    ephemeral_public_bytes = bytes.fromhex(ephemeral_public_key_hex)
    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), ephemeral_public_bytes)

    shared_secret = recipient_private.exchange(ec.ECDH(), ephemeral_public)
    key = hashlib.sha256(shared_secret).digest()[:24]

    iv = base64.b64decode(iv_base64)
    ciphertext = base64.b64decode(ciphertext_base64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    plaintext = unpad(padded, AES.block_size)
    return plaintext.decode('utf-8')

# ==================== Función para medir tiempo ====================
def measure_time(fn):
    """Ejecuta la función fn y retorna (resultado, tiempo en milisegundos)."""
    start = time.perf_counter()
    result = fn()
    end = time.perf_counter()
    return result, (end - start) * 1000  # ms

# ==================== Función Benchmark ====================
def run_benchmark():
    message = "Este es un mensaje de prueba secreto muy secreto."
    iterations = 100

    results = {
        "ChaCha20": {"enc": 0, "dec": 0, "size": 0},
        "AES192": {"enc": 0, "dec": 0, "size": 0},
        "RSA": {"enc": 0, "dec": 0, "size": 0},
        "ElGamal": {"enc": 0, "dec": 0, "size": 0}
    }

    # --- ChaCha20 ---
    for _ in range(iterations):
        key = os.urandom(32)
        nonce = os.urandom(12)
        encrypted, enc_time = measure_time(lambda: encrypt_message_chacha20(message, key, nonce))
        _, dec_time = measure_time(lambda: decrypt_message_chacha20(encrypted["ciphertext"], key, nonce, encrypted["tag"]))
        results["ChaCha20"]["enc"] += enc_time
        results["ChaCha20"]["dec"] += dec_time
        results["ChaCha20"]["size"] += len(encrypted["ciphertext"]) + len(encrypted["tag"])

    # --- AES-192 CBC ---
    for _ in range(iterations):
        key = os.urandom(24)
        encrypted, enc_time = measure_time(lambda: encrypt_aes192_cbc(message, key))
        _, dec_time = measure_time(lambda: decrypt_aes192_cbc(encrypted["ciphertext"], key, encrypted["iv"]))
        results["AES192"]["enc"] += enc_time
        results["AES192"]["dec"] += dec_time
        results["AES192"]["size"] += len(encrypted["ciphertext"]) + len(encrypted["iv"])

    # --- RSA OAEP ---
    rsa_public, rsa_private = generate_rsa_keys()
    for _ in range(iterations):
        ciphertext, enc_time = measure_time(lambda: encrypt_rsa(message, rsa_public))
        _, dec_time = measure_time(lambda: decrypt_rsa(ciphertext, rsa_private))
        results["RSA"]["enc"] += enc_time
        results["RSA"]["dec"] += dec_time
        results["RSA"]["size"] += len(ciphertext)

    # --- ElGamal (ECIES) ---
    elgamal_keys = generate_elgamal_keys()
    pub_el = elgamal_keys["publicKey"]
    priv_el = elgamal_keys["privateKey"]
    for _ in range(iterations):
        encrypted, enc_time = measure_time(lambda: encrypt_elgamal(message, pub_el))
        _, dec_time = measure_time(lambda: decrypt_elgamal(
            encrypted["ciphertext"],
            encrypted["iv"],
            encrypted["ephemeralPublicKey"],
            priv_el
        ))
        results["ElGamal"]["enc"] += enc_time
        results["ElGamal"]["dec"] += dec_time
        # Convertir tamaños: ciphertext e iv están en base64, la clave efímera en hex
        size_ciphertext = len(base64.b64decode(encrypted["ciphertext"]))
        size_iv = len(base64.b64decode(encrypted["iv"]))
        size_ephem = len(bytes.fromhex(encrypted["ephemeralPublicKey"]))
        results["ElGamal"]["size"] += size_ciphertext + size_iv + size_ephem

    # --- Mostrar resultados ---
    print("\nBenchmark de Cifradores")
    print("===========================")
    print("Mensaje de prueba:", message)
    for method, stats in results.items():
        avg_enc = stats["enc"] / iterations
        avg_dec = stats["dec"] / iterations
        avg_size = stats["size"] / iterations
        print(f"\n {method}")
        print(f"Promedio cifrado: {avg_enc:.3f} ms")
        print(f"Promedio descifrado: {avg_dec:.3f} ms")
        print(f"Tamaño promedio transmitido: {avg_size:.1f} bytes")
        
# ==================== Main ====================
if __name__ == "__main__":
    print("Iniciando benchmark de cifradores...\n")
    run_benchmark()
