import socket
import threading
import json

host = '127.0.0.1'
port = 55556

public_keys = {}

def handle_client(client_socket):
    try:
        package = client_socket.recv(1024).decode('utf-8')
        if ":" in package:
            operation, content = package.split(":", 1)
            if operation == "REGISTER":
                if ";" in content:
                    client_name, public_key = content.split(";", 1)
                    unserialized_public_key = tuple(json.loads(public_key))
                    public_keys[client_name] = unserialized_public_key
                    client_socket.send("REGISTERED".encode())
                else:
                    client_socket.send("Error in parsing content".encode())
            elif operation == "REQUEST":
                if content in public_keys:
                    client_socket.send(json.dumps(public_keys[content]).encode('utf-8'))
                else:
                    client_socket.send("nf".encode('utf-8'))
        else:
            client_socket.send("Invalid request".encode())
    except:
        print("Error handling client.")
    finally:
        client_socket.close()

def pka_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()
    print(f"PKA is running on {host}:{port}.")
    
    try:
        while True:
            client_socket, _ = server_socket.accept()
            threading.Thread(target=handle_client, args=(client_socket,)).start()
    except KeyboardInterrupt:
        print("\nShutting down PKA server.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    pka_server()
