import socket
import threading
import json
import sys
import random
import string
from rsa import rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify, rsa_generate_keys
from des import encrypt_text, decrypt_text

chat_host = '127.0.0.1'
chat_port = 55555

pka_host = '127.0.0.1'
pka_port = 55556

nickname = input("Enter your nickname: ")

my_publicKey, my_privateKey = rsa_generate_keys(bits=2048)

chat_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
chat_socket.connect((chat_host, chat_port))

def generate_des_key(length=8):
    if length > 8:
        raise ValueError("Length cannot be more than 8 characters.")
    # Generate a random hexadecimal key
    return ''.join(random.choices('0123456789ABCDEF', k=length))

def do_format(secretKey, message, sender, signature):
    full_message = f"{secretKey};{message}|{sender}?{signature}"
    return full_message

def register_with_pka(my_name, my_publicKey):
    pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    pka_socket.connect((pka_host, pka_port))
    key = json.dumps(my_publicKey)
    packet = f"REGISTER:{my_name};{key}"
    pka_socket.send(packet.encode('utf-8'))
    response = pka_socket.recv(1024).decode('utf-8')
    pka_socket.close()
    return response

def get_public_key_from_pka(their_name):
    pka_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    pka_socket.connect((pka_host, pka_port))
    packet = f"REQUEST:{their_name}"
    pka_socket.send(packet.encode('utf-8'))
    response = pka_socket.recv(1024).decode('utf-8')
    if response == "nf":
        print(f"User {their_name} not found")
    else:
        response = tuple(json.loads(response))
    pka_socket.close()
    return response

def receive():
    while True:
        try:
            message_package = chat_socket.recv(4096).decode('utf-8')
            if ":" in message_package:
                msg_type, content1 = message_package.split(":", 1)
                if msg_type == "system":
                    print(content1)
                elif msg_type == "user":
                    if ";" in content1:
                        encrypted_desKey, content2 = content1.split(";", 1)
                        if "|" in content2:
                            encrypted_message, content3 = content2.split("|", 1)
                            sender_name, signature = content3.split("?", 1)
                            try:
                                their_publicKey = get_public_key_from_pka(sender_name)
                                decrypted_desKey = rsa_decrypt(my_privateKey, encrypted_desKey)
                                if rsa_verify(their_publicKey, decrypted_desKey, signature):
                                    decrypted_message = decrypt_text(encrypted_message, decrypted_desKey)
                                    print(f"Decrypted Message from {sender_name}: {decrypted_message}")
                                else:
                                    print(f"Signature verification failed for {sender_name}'s message.")
                            except:
                                print("Error in decrypting message.")
        except:
            break

def write():
    while True:
        try:
            their_name = input("Who to send?: ").strip()
            if not their_name:
                print("Recipient name cannot be empty.")
                continue
            
            their_publicKey = get_public_key_from_pka(their_name)
            if their_publicKey == "nf":
                print(f"User {their_name} not found.")
                continue
            
            message = input("Enter your message: ").strip()
            if not message:
                print("Message cannot be empty.")
                continue
            
            des_key = generate_des_key()
            print(f"DES Key: {des_key}")  # Debugging untuk melihat kunci DES

            encrypted_message = encrypt_text(message, des_key)
            if not encrypted_message:
                print("Encryption failed. Check DES key and message.")
                continue

            signature = rsa_sign(my_privateKey, des_key)
            rsa_desKey = rsa_encrypt(their_publicKey, des_key)
            package = do_format(rsa_desKey, encrypted_message, nickname, signature)
            chat_socket.send(package.encode('utf-8'))
        except Exception as e:
            print(f"Error in write function: {e}")
            break


print(register_with_pka(nickname, my_publicKey))

receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()
