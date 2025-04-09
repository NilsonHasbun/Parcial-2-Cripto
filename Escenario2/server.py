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

def sender(conn, symmetric_key):
    """
    Hilo que permite al servidor escribir mensajes que son cifrados y enviados al interlocutor.
    """
    while True:
        message = input("Servidor: Escribe un mensaje (o 'exit' para terminar): ")
        if message.strip() == "exit":
            conn.sendall(message.encode())
            break
        iv = get_random_bytes(16)
        cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(message.encode()))
        # Se envía el IV concatenado con el ciphertext.
        conn.sendall(iv + ciphertext)
        print("Servidor: Mensaje cifrado enviado.")
    conn.close()
    print("Conexión cerrada por el servidor.")

def receiver(conn, symmetric_key):
    """
    Hilo que recibe mensajes cifrados, los descifra y los muestra.
    """
    while True:
        data = conn.recv(4096)
        if not data:
            print("Conexión finalizada por el cliente.")
            break
        try:
            if data.decode(errors='ignore').strip() == "exit":
                print("El cliente finalizó la comunicación.")
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
            print("Mensaje recibido:", plaintext.decode('utf-8', errors='replace'))
        except Exception as e:
            print("Error al descifrar el mensaje:", e)
    conn.close()
    print("Hilo receptor finalizado.")

def main():
    host = '0.0.0.0'
    port = 65433  # Puerto en el que el servidor escucha
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print("Servidor ECDH escuchando en {}:{}".format(host, port))
    
    conn, addr = server_socket.accept()
    print("Conexión aceptada de", addr)
    
    # Generar par de claves ECC en curva P-256
    server_key = ECC.generate(curve='P-256')
    server_pub = server_key.public_key()
    pub_point = server_pub.pointQ
    pub_data = {
        "curve": "P-256",
        "pub_x": str(pub_point.x),
        "pub_y": str(pub_point.y)
    }
    # Enviar la clave pública (que será interceptada/modificada por el atacante)
    conn.sendall(json.dumps(pub_data).encode())
    
    # Recibir la clave pública del interlocutor (normalmente reemplazada por el atacante)
    data = conn.recv(4096)
    if not data:
        print("No se recibió la clave pública del interlocutor.")
        conn.close()
        server_socket.close()
        return
    try:
        client_pub_data = json.loads(data.decode())
        client_pub_x = int(client_pub_data["pub_x"])
        client_pub_y = int(client_pub_data["pub_y"])
    except Exception as e:
        print("Error procesando la clave pública recibida:", e)
        conn.close()
        server_socket.close()
        return

    from Crypto.PublicKey.ECC import EccPoint
    client_point = EccPoint(client_pub_x, client_pub_y, curve='P-256')
    
    # Calcular secreto compartido (usando la coordenada x)
    shared_point = client_point * server_key.d
    shared_secret_int = int(shared_point.x)
    shared_secret_bytes = shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7) // 8, 'big')
    key_hash = SHA256.new(shared_secret_bytes).digest()
    symmetric_key = key_hash[:24]  # AES-192 requiere 24 bytes
    print("Clave simétrica derivada:", symmetric_key.hex())
    
    # Iniciar hilos para enviar y recibir mensajes simultáneamente
    send_thread = threading.Thread(target=sender, args=(conn, symmetric_key))
    recv_thread = threading.Thread(target=receiver, args=(conn, symmetric_key))
    
    send_thread.start()
    recv_thread.start()
    
    send_thread.join()
    recv_thread.join()
    
    server_socket.close()
    print("Servidor cerrado.")

if __name__ == "__main__":
    main()
