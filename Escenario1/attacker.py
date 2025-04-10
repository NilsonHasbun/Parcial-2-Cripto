import math
import time
import hashlib
from Crypto.Cipher import ChaCha20  # Cambiamos aquí

def baby_step_giant_step(g, y, p):
    m = math.ceil(math.sqrt(p - 1))  # m es la raíz cuadrada de p-1

    # Paso pequeño: calcular g^j mod p
    baby_steps = {pow(g, j, p): j for j in range(m)}

    # Paso grande: calcular g^(-m) mod p
    g_m_inverse = pow(g, p - 1 - m, p)

    # Paso grande: buscar coincidencias
    for i in range(m):
        # Calcular y * g^(-m * i) mod p
        giant_step = (y * pow(g_m_inverse, i, p)) % p
        if giant_step in baby_steps:
            return i * m + baby_steps[giant_step]

    return None  # No se encontró el logaritmo discreto

# Ejemplo de uso
g = 1970788  # Base
y1 = 2779038  # Llave publica del servidor
y2= 14047473 #Llave publica del cliente
p = 14330819  # Módulo

start_time = time.time()

result = baby_step_giant_step(g, y2, p)

end_time = time.time()
elapsed_time = end_time - start_time

data = bytes.fromhex('2efc9a41158937908deb829c30922a80d7d5')  # Tomar del "Data(x bytes)" en Wireshark

if result is not None:
    print(f"El logaritmo discreto es: {result}")
    simetricKey = pow(y1, result, p)
    key = hashlib.sha256(simetricKey.to_bytes((simetricKey.bit_length() + 7) // 8, byteorder='big')).digest()

    nonceU = data[:12]  # ChaCha20 usa nonce de 12 bytes
    cipherTextU = data[12:]
    decipher = ChaCha20.new(key=key, nonce=nonceU)
    text = decipher.decrypt(cipherTextU).decode()
    print(f"Texto: {text}")
else:
    print("No se encontró el logaritmo discreto.")

print(f"Tiempo transcurrido: {elapsed_time:.6f} segundos")
