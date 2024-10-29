import socket

# Fungsi dekripsi (contoh sederhana dengan decode)
def decrypt_message(encrypted_message):
    return bytes.fromhex(encrypted_message).decode('utf-8')

HOST = 'localhost'  
PORT = 65432  

# Membuat socket dan bind ke host dan port
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server listening on {HOST}:{PORT}...")

    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")

        while True:
            data = conn.recv(1024).decode('utf-8')

            if not data:
                print("No data received. Closing connection.")
                break

            if data == 'EXIT':
                print("Client requested to exit. Closing connection.")
                break

            # Dekripsi pesan dan tampilkan
            decrypted_message = decrypt_message(data)
            print(f"Encrypted message received: {data}")
            print(f"Decrypted message: {decrypted_message}")
