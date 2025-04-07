import math
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20

def baby_step_giant_step(g, A, p):
    """
    Resuelve el logaritmo discreto: encuentra x tal que A = g^x mod p.
    Utiliza el algoritmo baby-step giant-step.
    """
    m = math.isqrt(p - 1) + 1  # m = ceil(sqrt(p-1))
    baby_steps = {}
    cur = 1
    for j in range(m):
        baby_steps[cur] = j
        cur = (cur * g) % p

    # Calcular g^(-m) mod p utilizando el inverso modular de g
    inv = pow(g, p - 2, p)  # g^(-1) mod p (p es primo)
    factor = pow(inv, m, p)  # g^(-m) mod p
    y = A
    for i in range(m):
        if y in baby_steps:
            return i * m + baby_steps[y]
        y = (y * factor) % p
    return None

def main():
    # Datos capturados (ejemplo)
    # Estos valores se obtuvieron interceptando el intercambio DH con Wireshark.
    p = 227
    g = 12
    # Clave pública del servidor (A) interceptada
    server_public = 210  # Valor de ejemplo
    # Clave pública del cliente (B) interceptada
    client_public = 77   # Valor de ejemplo

    # Datos del mensaje interceptado (nonce + ciphertext)
    # Se asume que el mensaje cifrado fue enviado concatenando un nonce de 8 bytes y el ciphertext.
    nonce = bytes.fromhex("a1b2c3d4e5f60708")  # Ejemplo de nonce (8 bytes)
    ciphertext = bytes.fromhex("8f4d9d3a7c6e5b4a2e1f3c4b")  # Ejemplo de ciphertext

    # Intentar recuperar la clave privada del servidor (a) resolviendo el logaritmo discreto
    a = baby_step_giant_step(g, server_public, p)
    if a is None:
        print("No se pudo calcular el logaritmo discreto en el tiempo asignado.")
        return
    print("Clave privada del servidor (recuperada):", a)
    
    # Calcular el secreto compartido: shared_secret = (B)^a mod p
    shared_secret = pow(client_public, a, p)
    print("Secreto compartido (calculado):", shared_secret)
    
    # Derivar la clave simétrica usando SHA-256 sobre el secreto compartido
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
    symmetric_key = SHA256.new(secret_bytes).digest()
    print("Clave simétrica derivada:", symmetric_key.hex())
    
    # Intentar descifrar el mensaje interceptado con ChaCha20
    try:
        cipher = ChaCha20.new(key=symmetric_key, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        print("Mensaje descifrado:", plaintext.decode())
    except Exception as e:
        print("Error al descifrar el mensaje:", e)

if __name__ == "__main__":
    main()
