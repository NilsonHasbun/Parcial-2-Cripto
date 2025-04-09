import socket
import json
import math
import threading
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC

# Lock global para evitar múltiples accesos concurrentes al input
input_lock = threading.Lock()

def pad(data):
    padding_len = 16 - len(data) % 16
    return data + bytes([padding_len]) * padding_len

def unpad(data):
    return data[:-data[-1]]

def baby_step_giant_step(g, A, p):
    m = math.isqrt(p - 1) + 1
    baby_steps = {}
    cur = 1
    for j in range(m):
        baby_steps[cur] = j
        cur = (cur * g) % p
    inv = pow(g, p - 2, p)
    factor = pow(inv, m, p)
    y = A
    for i in range(m):
        if y in baby_steps:
            return i * m + baby_steps[y]
        y = (y * factor) % p
    return None

def forward(src, dst, decryption_key, encryption_key, label):
    """
    Reenvía mensajes de src a dst.
    Descifra el mensaje recibido, muestra su contenido y solicita al atacante (usando input)
    si desea modificar el mensaje. En ambos canales se permite la modificación.
    """
    while True:
        data = src.recv(4096)
        if not data:
            break
        try:
            if data.decode(errors='ignore').strip() == "exit":
                dst.sendall(data)
                print(label, "finaliza con exit.")
                break
        except:
            pass
        if len(data) < 16:
            print(label, "mensaje inválido (sin IV).")
            continue
        iv = data[:16]
        ciphertext = data[16:]
        try:
            cipher_dec = AES.new(decryption_key, AES.MODE_CBC, iv)
            plaintext_padded = cipher_dec.decrypt(ciphertext)
            plaintext = unpad(plaintext_padded)
            original_msg = plaintext.decode('utf-8', errors='replace')
            print(label, "mensaje descifrado:", original_msg)
            
            with input_lock:
                mod = input("Atacante [" + label + "]: Ingrese nuevo mensaje (o presione Enter para mantener el original): ")
            if mod.strip() != "":
                new_plaintext = mod.encode()
                print("Atacante reemplazó el mensaje por:", mod)
            else:
                new_plaintext = plaintext
                print("Atacante reenvía el mensaje original.")
            
            new_iv = get_random_bytes(16)
            cipher_enc = AES.new(encryption_key, AES.MODE_CBC, new_iv)
            new_ciphertext = cipher_enc.encrypt(pad(new_plaintext))
            dst.sendall(new_iv + new_ciphertext)
        except Exception as e:
            print(label, "error al procesar el mensaje:", e)

def handle_client(client_conn, server_host, server_port):
    # Conectar al servidor
    server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_conn.connect((server_host, server_port))
    print("Conectado al servidor en {}:{}".format(server_host, server_port))
    
    # Generar dos pares de claves ECC para el atacante: uno para el canal con el cliente, otro para el canal con el servidor.
    attacker_key_client = ECC.generate(curve='P-256')
    attacker_pub_client = attacker_key_client.public_key()
    attacker_key_server = ECC.generate(curve='P-256')
    attacker_pub_server = attacker_key_server.public_key()
    
    from Crypto.PublicKey.ECC import EccPoint
    attacker_pub_client_data = {
        "curve": "P-256",
        "pub_x": str(attacker_pub_client.pointQ.x),
        "pub_y": str(attacker_pub_client.pointQ.y)
    }
    attacker_pub_server_data = {
        "curve": "P-256",
        "pub_x": str(attacker_pub_server.pointQ.x),
        "pub_y": str(attacker_pub_server.pointQ.y)
    }
    
    # 1. Interceptar el mensaje de parámetros DH enviado por el servidor
    server_message = server_conn.recv(4096)
    if not server_message:
        print("No se recibieron datos del servidor.")
        client_conn.close()
        server_conn.close()
        return
    print("Mensaje recibido del servidor:", server_message.decode())
    try:
        dh_params = json.loads(server_message.decode())
        # Para fines académicos, usamos valores pequeños (estos se podrían reemplazar por los reales)
        p = 227
        g = 12
        server_pub_x = int(dh_params["pub_x"])
        server_pub_y = int(dh_params["pub_y"])
        server_pub_point = EccPoint(server_pub_x, server_pub_y, curve='P-256')
    except Exception as e:
        print("Error al parsear parámetros del servidor:", e)
        client_conn.close()
        server_conn.close()
        return
    print("Parámetros del servidor interceptados: p =", p, ", g =", g)
    
    # Enviar al cliente la clave pública del atacante (para el canal cliente)
    client_conn.sendall(json.dumps(attacker_pub_client_data).encode())
    print("Enviado al cliente la clave pública del atacante (para su conexión).")
    
    # 2. Interceptar la clave pública del cliente
    client_message = client_conn.recv(4096)
    if not client_message:
        print("No se recibió la clave pública del cliente.")
        client_conn.close()
        server_conn.close()
        return
    print("Mensaje recibido del cliente:", client_message.decode())
    try:
        client_dh = json.loads(client_message.decode())
        client_pub_x = int(client_dh["pub_x"])
        client_pub_y = int(client_dh["pub_y"])
        client_pub_point = EccPoint(client_pub_x, client_pub_y, curve='P-256')
    except Exception as e:
        print("Error al parsear la clave pública del cliente:", e)
        client_conn.close()
        server_conn.close()
        return
    print("Clave pública del cliente interceptada.")
    
    # Enviar al servidor la clave pública del atacante (para el canal con el servidor)
    server_conn.sendall(json.dumps(attacker_pub_server_data).encode())
    print("Enviado al servidor la clave pública del atacante (para su conexión).")
    
    # 3. Calcular las llaves compartidas:
    # Con el cliente:
    shared_point_client = client_pub_point * attacker_key_client.d
    shared_secret_client_int = int(shared_point_client.x)
    shared_secret_client_bytes = shared_secret_client_int.to_bytes((shared_secret_client_int.bit_length()+7)//8, 'big')
    symmetric_key_client = SHA256.new(shared_secret_client_bytes).digest()[:24]
    print("Clave simétrica para conexión con el cliente:", symmetric_key_client.hex())
    
    # Con el servidor:
    shared_point_server = server_pub_point * attacker_key_server.d
    shared_secret_server_int = int(shared_point_server.x)
    shared_secret_server_bytes = shared_secret_server_int.to_bytes((shared_secret_server_int.bit_length()+7)//8, 'big')
    symmetric_key_server = SHA256.new(shared_secret_server_bytes).digest()[:24]
    print("Clave simétrica para conexión con el servidor:", symmetric_key_server.hex())
    
    # Iniciar hilos para reenviar mensajes en ambas direcciones:
    thread_client_to_server = threading.Thread(
        target=forward,
        args=(client_conn, server_conn, symmetric_key_client, symmetric_key_server, "Cliente -> Servidor")
    )
    thread_server_to_client = threading.Thread(
        target=forward,
        args=(server_conn, client_conn, symmetric_key_server, symmetric_key_client, "Servidor -> Cliente")
    )
    
    thread_client_to_server.start()
    thread_server_to_client.start()
    
    thread_client_to_server.join()
    thread_server_to_client.join()
    
    client_conn.close()
    server_conn.close()
    print("Conexiones cerradas.")

def attacker_main():
    attacker_listen_host = '0.0.0.0'
    attacker_listen_port = 65434  # Puerto donde el atacante escucha la conexión del cliente
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.bind((attacker_listen_host, attacker_listen_port))
    listen_sock.listen(1)
    print("Atacante escuchando en {}:{}".format(attacker_listen_host, attacker_listen_port))
    while True:
        client_conn, client_addr = listen_sock.accept()
        print("Cliente conectado desde", client_addr)
        threading.Thread(target=handle_client, args=(client_conn, 'localhost', 65433)).start()

if __name__ == "__main__":
    attacker_main()

