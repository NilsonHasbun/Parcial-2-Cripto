import socket
import threading
import json
from diffiHellman import Keys
from Crypto.Cipher import ChaCha20   # Cambiamos aquí
from Crypto.Random import get_random_bytes
import hashlib


with open('parameters.json', 'r') as file:
    parameters = json.load(file)

# Tomamos el primer conjunto de parámetros
params = parameters['parameters'][2]
p = params['p']
q = params['q']
g = params['g']

client = Keys(p, q, g)
client.change_pvk()
client.generate_public_key()  # Se envía al cliente
public_key = client.pk 
key = None

def receive_messages(client_socket):
    global key
    k = True
    # Escuchar periódicamente el canal
    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break

            # El primer mensaje contiene la llave
            if k:
                client.generate_simetric_key(int.from_bytes(data, byteorder='big'))
                key = hashlib.sha256(client.simetricKey.to_bytes((client.simetricKey.bit_length()+7)//8, byteorder='big')).digest()
                print(f"llave: {key.hex()}")
                k = False
            else:
                # Divide los datos en nonce y mensaje
                nonceS = data[:12]  # ChaCha20 usa nonce de 12 bytes
                cipherText = data[12:]
                # Decifra el mensaje con la llave y el nonce correspondiente
                decipher = ChaCha20.new(key=key, nonce=nonceS)
                text = decipher.decrypt(cipherText).decode()
                print(f"Servidor: {text}")
        except ConnectionResetError:
            break

    client_socket.close()

def start_client(server_ip, server_port):
    global key, public_key
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   
    client_socket.connect((server_ip, server_port))
   
    receiver_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receiver_thread.start()

    while key is None:
        pass

    client_socket.sendall(public_key.to_bytes((public_key.bit_length()+7)//8, byteorder='big'))

    while True:
        message = input("Tu mensaje: ")
        nonce = get_random_bytes(12)  # Nonce de 12 bytes
        cipher = ChaCha20.new(key=key, nonce=nonce)
        cipherText = cipher.encrypt(message.encode())
        mess = nonce + cipherText
        client_socket.sendall(mess)

if __name__ == "__main__":
    server_ip = 'localhost'  # Cambia esto a la IP del servidor
    server_port = 12345
    start_client(server_ip, server_port)
