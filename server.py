import socket
from DES import encrypt, bin2hex, hex_to_string

def reverse_round_keys(rkb, rk):
    rkb.reverse()
    rk.reverse()
    return rkb, rk

def main():
    host = 'localhost'
    port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        print("Waiting for connection...")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")

            #Terima cipher text dari client
            cipher_text = conn.recv(1024).decode()
            print("Received Cipher Text:", cipher_text)

            #pisahkan rkb dan rk yang diterima sebagai string
            round_keys_data = conn.recv(4096).decode()
            rkb_str, rk_str = round_keys_data.split('|')

            # Convert to list
            rkb = eval(rkb_str)
            rk = eval(rk_str)

            # Balik urutan round keys untuk proses dekripsi (16 ke 1)
            rkb, rk = reverse_round_keys(rkb, rk)

            print("Decryption in Progress...")
            decrypted_bin = encrypt(cipher_text, rkb, rk)
            decrypted_text = bin2hex(decrypted_bin)
            string_text = hex_to_string(decrypted_text)

            print("Final Decrypted Text (Hex):", decrypted_text)
            print("Final Decrypted Text (String):", string_text)
            print("Decryption process complete.")


if __name__ == "__main__":
    main()
