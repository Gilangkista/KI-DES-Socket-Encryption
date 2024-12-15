import json
import socket
import threading
from DES import string_to_hex, hex2bin, bin2hex, encrypt, pad_input, round, split_into_blocks, hex_to_string
from rsa import primefiller, setkeys, encoder, decoder

# Setup DES and RSA Keys
keyraw = "AABB09182736CCDD"
prime = primefiller(set())
public_key, secret_key = setkeys(prime)
key = string_to_hex(keyraw)
key = hex2bin(key)
rk, rkb = round(key)

# Flag untuk sinkronisasi thread
is_running = True

# Choosing Nickname
nickname = input("Choose your nickname: ")

# Connecting To Server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 55555))

# Listening to Server and Sending Nickname
def receive():
    global is_running
    while is_running:
        try:
            message = client.recv(1024)
            if not message:
                print("Koneksi ditutup oleh server.")
                is_running = False
                client.close()
                break

            try:
                # Coba decode sebagai UTF-8, fallback ke raw bytes jika gagal
                decoded_message = message.decode('utf-8', errors='replace')
                print(decoded_message)
            except Exception as e:
                print(f"Pesan biner diterima: {message}")
                continue

            # Logic tambahan Anda di sini
            if decoded_message == 'NICK':
                client.send(nickname.encode())

            elif "penerima" in decoded_message:
                user = decoded_message.split('= ', 1)
                if nickname == user[1]:
                    pesan = 'public_key = {}'.format(public_key)
                    client.send(pesan.encode())
            elif ":" in decoded_message:
                try:
                    temp = decoded_message
                    part2 = temp.split('with encoded key: ', 1)
                    part1 = part2[0].split(': ')

                    # Decode the encoded key
                    encoded_key_json = json.loads(part2[1])  # Load JSON encoded key
                    # Decode the encoded key
                    decoded_des_key = decoder(json.loads(part2[1]), secret_key)
                    print("Decoded DES Key (Raw):", decoded_des_key)

                    # Konversi menjadi HEX jika bukan dalam format string
                    if isinstance(decoded_des_key, bytes):
                        decoded_des_key = decoded_des_key.decode('utf-8', errors='replace')  # Safely decode bytes to string
                    print("Decoded DES Key (UTF-8):", decoded_des_key)

                    key_des = string_to_hex(decoded_des_key)  # Ensure conversion to hex
                    key_des = hex2bin(key_des)               # Convert hex to binary
           # Convert hex to binary
                    rk, rkb = round(key_des)                 # Generate keys
                    rkb_rev = rkb[::-1]
                    rk_rev = rk[::-1]

                    # Convert part1[1] (message) to hex
                    part1_1_bytes = part1[1].encode('utf-8')  # Ensure bytes input
                    part1_1_hex = string_to_hex(part1_1_bytes.decode())
                    print("Encrypted Data (Hex):", part1_1_hex)

                    # Decrypt the message
                    bloks = split_into_blocks(part1_1_hex, block_size=16)
                    hasil = ''
                    for blok in bloks:
                        decrypted_blok = encrypt(blok, rkb_rev, rk_rev)
                        hasil += hex_to_string(bin2hex(decrypted_blok))
                    
                    print('Hasil:', hasil)

                except Exception as e:
                    print(f"Error saat mendekripsi: {e}")

        except Exception as e:
            print(f"Error saat menerima pesan: {e}")
            is_running = False
            client.close()
            break




# Sending Messages To Server
def write():
    global is_running
    encoded_message = ''
    try:
        while is_running:
            try:
                kirim = input("Penerima: ")
                if kirim == "END":
                    print("Menutup koneksi...")
                    is_running = False
                    client.close()
                    break

                # Input message
                user_inp = input("Pesan: ")
                if user_inp == "END":
                    print("Menutup koneksi...")
                    is_running = False
                    client.close()
                    break

                # Split and Encrypt message
                message_blok = split_into_blocks(user_inp)
                for blok in message_blok:
                    blok = pad_input(blok)
                    blok = string_to_hex(blok)
                    cipher_blok = encrypt(blok, rkb, rk)
                    encoded_message += bin2hex(cipher_blok)

                # Encode key and send message
                encoded_des_key = encoder(keyraw, public_key)
                message = '{}: {} with encoded key: {}'.format(nickname, encoded_message, encoded_des_key)
                client.send(message.encode())
                print("Terkirim:", message)
                encoded_message = ''
            except EOFError:
                print("EOFError: Input dihentikan.")
                is_running = False
                break
    except Exception as e:
        print(f"Error dalam thread write: {e}")
        is_running = False
    finally:
        client.close()

# Starting Threads For Listening And Writing
receive_thread = threading.Thread(target=receive)
write_thread = threading.Thread(target=write)

receive_thread.start()
write_thread.start()

receive_thread.join()
write_thread.join()
