import socket
import json
import threading
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def pad(data):
    padding_len = 16 - len(data) % 16
    return data + bytes([padding_len]) * padding_len

def unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

def sender(sock, symmetric_key):
    """
    Hilo que permite al cliente escribir mensajes y enviarlos cifrados al servidor (pasando por el atacante).
    """
    while True:
        message = input("Cliente: Escribe un mensaje (o 'exit' para terminar): ")
        if message.strip() == "exit":
            sock.sendall(message.encode())
            break
        iv = get_random_bytes(16)
        cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(message.encode()))
        # Enviar IV + ciphertext
        sock.sendall(iv + ciphertext)
        print("Cliente: Mensaje cifrado enviado.")
    sock.close()
    print("Conexión cerrada por el cliente (hilo de envío).")

def receiver(sock, symmetric_key):
    """
    Hilo que recibe mensajes cifrados, los descifra y los muestra en la consola del cliente.
    """
    while True:
        data = sock.recv(4096)
        if not data:
            print("Conexión finalizada por el servidor (o atacante).")
            break
        try:
            if data.decode(errors='ignore').strip() == "exit":
                print("El servidor finalizó la comunicación.")
                break
        except Exception:
            pass
        if len(data) < 16:
            print("Mensaje recibido inválido (sin IV).")
            continue
        iv = data[:16]
        ciphertext = data[16:]
        try:
            cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
            plaintext_padded = cipher.decrypt(ciphertext)
            plaintext = unpad(plaintext_padded)
            print("Mensaje recibido en el cliente:", plaintext.decode('utf-8', errors='replace'))
        except Exception as e:
            print("Error al descifrar el mensaje en el cliente:", e)
    sock.close()
    print("Hilo receptor del cliente finalizado.")

def main():
    # El cliente se conecta al atacante (MitM)
    host = 'localhost'
    port = 65434  # El atacante escucha en este puerto
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    print("Cliente conectado a {}:{}".format(host, port))
    
    # Recibir la clave pública (JSON) enviada (probablemente modificada por el atacante)
    data = client_socket.recv(4096)
    if not data:
        print("No se recibió la clave pública.")
        client_socket.close()
        return
    try:
        server_pub_data = json.loads(data.decode())
        server_pub_x = int(server_pub_data["pub_x"])
        server_pub_y = int(server_pub_data["pub_y"])
    except Exception as e:
        print("Error al procesar la clave pública recibida:", e)
        client_socket.close()
        return
    
    from Crypto.PublicKey.ECC import EccPoint
    server_point = EccPoint(server_pub_x, server_pub_y, curve='P-256')
    
    # Generar par de claves ECC para el cliente
    client_key = ECC.generate(curve='P-256')
    client_pub = client_key.public_key()
    pub_point = client_pub.pointQ
    client_data = {
        "curve": "P-256",
        "pub_x": str(pub_point.x),
        "pub_y": str(pub_point.y)
    }
    # Enviar la clave pública del cliente (interceptada por el atacante)
    client_socket.sendall(json.dumps(client_data).encode())
    
    # Calcular el secreto compartido
    shared_point = server_point * client_key.d
    shared_secret_int = int(shared_point.x)
    shared_secret_bytes = shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7) // 8, 'big')
    key_hash = SHA256.new(shared_secret_bytes).digest()
    symmetric_key = key_hash[:24]  # AES-192 (24 bytes)
    print("Clave simétrica derivada (cliente):", symmetric_key.hex())
    
    # Iniciar hilos para enviar y recibir
    send_thread = threading.Thread(target=sender, args=(client_socket, symmetric_key))
    recv_thread = threading.Thread(target=receiver, args=(client_socket, symmetric_key))
    send_thread.start()
    recv_thread.start()
    
    send_thread.join()
    recv_thread.join()
    print("Cliente terminado.")

if __name__ == "__main__":
    main()
