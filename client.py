# client.py
import socket
from des import encrypt

KEY = "10101010"  
def send_message(host='localhost', port=65432):
    message = input("Enter message to send: ")
    encrypted_message = encrypt(message, KEY)
    print(f"Encrypted message: {encrypted_message}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(encrypted_message.encode())
        print("Message sent to server.")

if __name__ == "__main__":
    send_message()
