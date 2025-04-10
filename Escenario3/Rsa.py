from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def generate_rsa_keys():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    # Serialización de la clave privada (sin cifrado)
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # Serialización de la clave pública en formato SPKI (X.509)
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return public_key_pem, private_key_pem


def encrypt_rsa(message: str, public_key_pem: str) -> bytes:
  
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    ciphertext = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
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
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode('utf-8')


# Ejemplo de uso
if __name__ == '__main__':
    # Generar claves RSA
    public_key, private_key = generate_rsa_keys()
    print("Clave Pública:\n", public_key)
    print("Clave Privada:\n", private_key)

    # Mensaje a cifrar
    message = "Mensaje secreto mediante RSA OAEP en Python"
    print("Mensaje original:", message)

    # Cifrado
    ciphertext = encrypt_rsa(message, public_key)
    print("Ciphertext (hex):", ciphertext.hex())

    # Descifrado
    decrypted_message = decrypt_rsa(ciphertext, private_key)
    print("Mensaje descifrado:", decrypted_message)
