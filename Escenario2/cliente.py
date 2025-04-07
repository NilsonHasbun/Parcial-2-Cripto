import socket
import json
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pad(data):
    padding_len = 16 - len(data) % 16
    return data + bytes([padding_len] * padding_len)

def main():
    host = 'localhost'
    port = 65434  # Se conecta al atacante (MitM) en lugar de al servidor real
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print("Conectado al servidor ECDH (a través del atacante) {}:{}".format(host, port))

    # Recibir la clave pública (JSON) del interlocutor (será modificada por el atacante)
    data = client_socket.recv(4096)
    server_pub_data = json.loads(data.decode())
    server_pub_x = int(server_pub_data["pub_x"])
    server_pub_y = int(server_pub_data["pub_y"])
    from Crypto.PublicKey.ECC import EccPoint
    server_point = EccPoint(server_pub_x, server_pub_y, curve='P-256')

    # Generar par de claves ECC para el cliente
    client_key = ECC.generate(curve='P-256')
    client_pub = client_key.public_key()
    client_point = client_pub.pointQ
    client_pub_data = {"curve": "P-256", "pub_x": str(client_point.x), "pub_y": str(client_point.y)}
    # Enviar clave pública al interlocutor (que en realidad es el atacante)
    client_socket.sendall(json.dumps(client_pub_data).encode())

    # Calcular el secreto compartido
    shared_point = server_point * client_key.d
    shared_secret_int = int(shared_point.x)
    shared_secret_bytes = shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7) // 8, byteorder='big')
    key_hash = SHA256.new(shared_secret_bytes).digest()
    symmetric_key = key_hash[:24]  # Clave para AES-192
    print("Clave simétrica derivada:", symmetric_key.hex())

    # Bucle de comunicación: enviar mensajes cifrados con AES-192 en modo CBC
    while True:
        message = input("Escribe un mensaje (o 'exit' para salir): ")
        iv = get_random_bytes(16)
        cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(message.encode()))
        client_socket.sendall(iv + ciphertext)
        print("Mensaje cifrado enviado.")
        if message.strip() == "exit":
            break

    client_socket.close()
    print("Conexión cerrada.")

if __name__ == "__main__":
    main()
