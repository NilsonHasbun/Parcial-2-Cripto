import socket
import json
from Crypto.Util.number import getRandomRange
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes

def main():
    host = 'localhost'
    port = 65432
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print("Conectado al servidor {}:{}".format(host, port))
    
    # Recibir parámetros DH del servidor (p, g y la clave pública A)
    data = client_socket.recv(4096)
    server_params = json.loads(data.decode())
    p = server_params["p"]
    g = server_params["g"]
    server_public = server_params["A"]
    print("Parámetros recibidos del servidor: p={}, g={}, A={}".format(p, g, server_public))
    
    # Generar clave privada y calcular la clave pública del cliente
    private_key = getRandomRange(2, p)
    public_key = pow(g, private_key, p)
    print("Clave pública del cliente:", public_key)
    
    # Enviar la clave pública del cliente al servidor (formato JSON)
    client_dh = json.dumps({"B": public_key})
    client_socket.sendall(client_dh.encode())
    
    # Calcular el secreto compartido
    shared_secret = pow(server_public, private_key, p)
    print("Secreto compartido:", shared_secret)
    
    # Derivar la clave simétrica utilizando SHA-256 sobre el secreto compartido
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
    symmetric_key = SHA256.new(secret_bytes).digest()  # 32 bytes
    print("Clave simétrica derivada (SHA-256):", symmetric_key.hex())
    
    # Bucle de comunicación: enviar mensajes cifrados hasta que el usuario escriba "exit"
    while True:
        message = input("Escribe un mensaje (o 'exit' para salir): ")
        if message.strip() == "exit":
            client_socket.sendall(message.encode())
            break
        
        # Encriptar el mensaje utilizando ChaCha20 con un nonce de 8 bytes
        nonce = get_random_bytes(8)
        cipher = ChaCha20.new(key=symmetric_key, nonce=nonce)
        ciphertext = cipher.encrypt(message.encode())
        
        # Enviar el nonce concatenado con el ciphertext
        client_socket.sendall(nonce + ciphertext)
        print("Mensaje cifrado enviado.")
    
    client_socket.close()
    print("Conexión cerrada.")

if __name__ == "__main__":
    main()
