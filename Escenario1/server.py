import socket
import json
from Crypto.Util.number import getRandomRange
from Crypto.Hash import SHA256
from Crypto.Cipher import ChaCha20

def load_parameters():
    with open("params.json", "r") as f:
        data = json.load(f)
    return data["parameters"]

def main():
    # Cargar parámetros y seleccionar el primero
    parameters = load_parameters()
    param = parameters[0]
    p = param["p"]
    q = param["q"]
    g = param["g"]

    # Configurar el servidor TCP
    host = '0.0.0.0'
    port = 65432
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print("Servidor escuchando en {}:{}".format(host, port))

    conn, addr = server_socket.accept()
    print("Conexión aceptada de", addr)

    # Generar clave privada y calcular la clave pública del servidor
    private_key = getRandomRange(2, q)
    public_key = pow(g, private_key, p)
    print("Clave pública del servidor:", public_key)

    # Enviar parámetros DH y la clave pública del servidor al cliente (formato JSON)
    dh_params = json.dumps({"p": p, "g": g, "A": public_key})
    conn.sendall(dh_params.encode())

    # Recibir la clave pública del cliente
    client_data = conn.recv(4096)
    if not client_data:
        print("No se recibió información del cliente.")
        conn.close()
        return

    client_json = json.loads(client_data.decode())
    client_public = client_json["B"]
    print("Clave pública del cliente:", client_public)

    # Calcular el secreto compartido
    shared_secret = pow(client_public, private_key, p)
    print("Secreto compartido:", shared_secret)

    # Derivar la clave simétrica usando SHA-256 sobre el secreto compartido
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')
    symmetric_key = SHA256.new(secret_bytes).digest()  # 32 bytes
    print("Clave simétrica derivada (SHA-256):", symmetric_key.hex())

    # Bucle de comunicación: el servidor espera mensajes cifrados con ChaCha20
    while True:
        data = conn.recv(4096)
        if not data:
            print("El cliente se desconectó.")
            break

        # Si el cliente envía "exit", se finaliza la comunicación
        if data.decode(errors="ignore").strip() == "exit":
            print("El cliente ha finalizado la comunicación.")
            break

        # Se espera que el mensaje tenga el nonce (8 bytes) y el ciphertext
        if len(data) < 8:
            print("Mensaje recibido inválido: no contiene nonce y ciphertext.")
            continue

        nonce = data[:8]
        ciphertext = data[8:]
        try:
            cipher = ChaCha20.new(key=symmetric_key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)
            print("Mensaje recibido (descifrado):", plaintext.decode())
        except Exception as e:
            print("Error al descifrar el mensaje:", e)

    conn.close()
    server_socket.close()
    print("Servidor cerrado.")

if __name__ == "__main__":
    main()
