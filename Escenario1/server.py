import socket
import threading
import hashlib
import json
from Crypto.Cipher import ChaCha20   # Cambiamos aquí
from Crypto.Random import get_random_bytes
from diffiHellman import Keys

with open('parameters.json', 'r') as file:
    parameters = json.load(file)

# Tomamos el primer conjunto de parámetros
params = parameters['parameters'][2]
p = params['p']
q = params['q']
g = params['g']

server = Keys(p, q, g)
server.change_pvk()
server.generate_public_key()  # Se envía al cliente
public_key = server.pk

def handle_client(client_socket):
    c = True
    while True:
        try:
            # Recibir datos del cliente
            data = client_socket.recv(1024)
            if not data:
                break
            if c:
                server.generate_simetric_key(int.from_bytes(data, byteorder='big'))
                key = hashlib.sha256(server.simetricKey.to_bytes((server.simetricKey.bit_length() + 7) // 8, byteorder='big')).digest()
                print(f"llave: {key.hex()}")
                c = False
            else:
                nonceU = data[:12]  # ChaCha20 usa nonce de 12 bytes
                cipherTextU = data[12:]
                decipher = ChaCha20.new(key=key, nonce=nonceU)
                text = decipher.decrypt(cipherTextU).decode()
                print(f"Cliente: {text}")

                # Enviar una respuesta (texto plano)
                response = input("Tu respuesta: ")

                nonce = get_random_bytes(12)  # Nonce de 12 bytes
                cipher = ChaCha20.new(key=key, nonce=nonce)

                cipherText = cipher.encrypt(response.encode())
                mess = nonce + cipherText
                client_socket.sendall(mess)

        except ConnectionResetError:
            break
    
    client_socket.close()

def start_server(host='0.0.0.0', port=12345):
    global public_key
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f"Esperando conexión en {host}:{port}...")
    
    client_socket, client_address = server_socket.accept()
    client_socket.sendall(public_key.to_bytes((public_key.bit_length() + 7) // 8, byteorder='big'))
    print(f"Conectado a {client_address}")
    
    client_handler = threading.Thread(target=handle_client, args=(client_socket,))
    client_handler.start()

if __name__ == "__main__":
    start_server()
