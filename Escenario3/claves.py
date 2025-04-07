from Crypto.PublicKey import RSA, ElGamal
from Crypto.Cipher import PKCS1_OAEP, ChaCha20
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes, getRandomRange

def rsa_oaep_demo(message):
    # Generar par de claves RSA (2048 bits)
    key = RSA.generate(2048)
    public_key = key.publickey()
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(message.encode())
    print("RSA OAEP:")
    print("  Longitud del ciphertext:", len(ciphertext), "bytes")
    return ciphertext, key

def elgamal_demo(message):
    # Generar par de claves ElGamal (1024 bits para la demostración)
    key = ElGamal.generate(1024, Random.new().read)
    p = key.p
    g = key.g
    y = key.y
    # Convertir el mensaje a entero
    m_int = bytes_to_long(message.encode())
    if m_int >= p:
        raise ValueError("El mensaje es demasiado largo para el cifrado ElGamal en esta demostración.")
    # Elegir un número aleatorio r entre 1 y p-2
    r = getRandomRange(1, p - 1)
    # Calcular c1 = g^r mod p y c2 = m * y^r mod p
    c1 = pow(g, r, p)
    c2 = (m_int * pow(y, r, p)) % p
    # Convertir los números a bytes para estimar la longitud
    c1_bytes = long_to_bytes(c1)
    c2_bytes = long_to_bytes(c2)
    total_length = len(c1_bytes) + len(c2_bytes)
    print("ElGamal:")
    print("  Longitud total del ciphertext (c1 + c2):", total_length, "bytes")
    ciphertext = (c1_bytes, c2_bytes)
    return ciphertext, key

def chacha20_demo(message):
    key = get_random_bytes(32)
    nonce = get_random_bytes(8)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext = cipher.encrypt(message.encode())
    total_length = len(nonce) + len(ciphertext)
    print("ChaCha20 (cifrado simétrico):")
    print("  Longitud total (nonce + ciphertext):", total_length, "bytes")
    return ciphertext, key, nonce

def main():
    message = "Mensaje de prueba para comunicaciones asimétricas y simétricas."
    print("Mensaje:", message)
    print()
    
    # Demostración con RSA OAEP
    rsa_ciphertext, rsa_key = rsa_oaep_demo(message)
    print()
    # Demostración con ElGamal
    try:
        elgamal_ciphertext, elgamal_key = elgamal_demo(message)
    except ValueError as e:
        print("Error en ElGamal:", e)
    print()
    # Demostración con ChaCha20
    chacha20_ciphertext, chacha20_key, chacha20_nonce = chacha20_demo(message)
    print()

if __name__ == "__main__":
    main()
