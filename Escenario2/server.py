import socket
import json
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

def main():
    host = '0.0.0.0'
    port = 65433  # Puerto para el servidor (diferente al de escenario 1)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print("Servidor ECDH escuchando en {}:{}".format(host, port))

    conn, addr = server_socket.accept()
    print("Conexión aceptada de", addr)

    # Generar par de claves ECC para el servidor
    server_key = ECC.generate(curve='P-256')
    server_pub = server_key.public_key()
    pub_point = server_pub.pointQ
    pub_data = {"curve": "P-256", "pub_x": str(pub_point.x), "pub_y": str(pub_point.y)}
    # Enviar clave pública al otro extremo (en formato JSON)
    conn.sendall(json.dumps(pub_data).encode())

    # Recibir clave pública del otro extremo
    client_data = conn.recv(4096)
    client_pub_data = json.loads(client_data.decode())
    client_pub_x = int(client_pub_data["pub_x"])
    client_pub_y = int(client_pub_data["pub_y"])
    from Crypto.PublicKey.ECC import EccPoint
    client_point = EccPoint(client_pub_x, client_pub_y, curve='P-256')

    # Calcular el secreto compartido: multiplicar el punto recibido por la clave privada
    shared_point = client_point * server_key.d
    shared_secret_int = int(shared_point.x)  # Se utiliza la coordenada X
    shared_secret_bytes = shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7) // 8, byteorder='big')
    key_hash = SHA256.new(shared_secret_bytes).digest()
    symmetric_key = key_hash[:24]  # AES-192 requiere 24 bytes
    print("Clave simétrica derivada:", symmetric_key.hex())

    # Bucle de comunicación: recibir mensajes cifrados (IV + ciphertext)
    while True:
        data = conn.recv(4096)
        if not data:
            print("El cliente se desconectó.")
            break
        if len(data) < 16:
            print("Mensaje recibido inválido.")
            continue
        iv = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
        plaintext_padded = cipher.decrypt(ciphertext)
        try:
            plaintext = unpad(plaintext_padded).decode()
        except Exception as e:
            print("Error al eliminar padding:", e)
            plaintext = plaintext_padded.decode(errors="ignore")
        print("Mensaje recibido (descifrado):", plaintext)
        if plaintext.strip() == "exit":
            print("Cliente finalizó la comunicación.")
            break

    conn.close()
    server_socket.close()
    print("Servidor cerrado.")

if __name__ == "__main__":
    main()
