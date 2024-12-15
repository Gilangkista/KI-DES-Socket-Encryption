import threading
import socket

host = '127.0.0.1'
port = 55555

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()

clients = []
nicknames = []

def broadcast(message, msg_type="user"):
    full_message = f"{msg_type}:{message}"
    for client in clients:
        client.send(full_message.encode('utf-8'))

def handle(client):
    while True:
        try:
            message = client.recv(4096).decode('utf-8')
            broadcast(message, msg_type="user")
        except:
            if client in clients:
                index = clients.index(client)
                clients.remove(client)
                client.close()
                nickname = nicknames[index]
                broadcast(f"{nickname} left the chat", msg_type="system")
                nicknames.remove(nickname)
            break

def receive():
    print(f"Chat server running on {host}:{port}")
    while True:
        try:
            client, address = server.accept()
            client.send('NICK'.encode('utf-8'))
            nickname = client.recv(4096).decode('utf-8')
            nicknames.append(nickname)
            clients.append(client)
            print(nickname)
            # broadcast(f"{nickname} joined the chat", msg_type="system")
            threading.Thread(target=handle, args=(client,)).start()
        except KeyboardInterrupt:
            break

    print("Shutting down chat server.")
    for client in clients:
        client.close()
    server.close()

if __name__ == "__main__":
    receive()
