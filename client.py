import socket
import threading
from DES import string_to_hex, hex2bin, bin2hex, encrypt, pad_input, round, des_encrypt_block,split_into_blocks,hex_to_string
from rsa import primefiller,setkeys,encoder,decrypt,decoder
keyraw = 'AABB09182736CCDD'
prime = set()
prime = primefiller(prime)
public_key,secret_key=setkeys(prime)
print("p_key = ", public_key)
key = string_to_hex(keyraw)
key = hex2bin(key)
rk,rkb = round(key)

# print(rkb)

# Choosing Nickname
nickname = input("Choose your nickname: ")


# Connecting To Server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 55555))

# Listening to Server and Sending Nickname
def receive():
    while True:
        try:
            # Receive Message From Server
            # If 'NICK' Send Nickname
            message = client.recv(1024).decode('ascii')
            # print(message)
            if message == 'NICK':
                client.send(nickname.encode('ascii'))
            
            elif "penerima" in message:
                user = message.split('= ',1)
                if nickname == user[1]:
                    # public_key = str(public_key)
                    pesan = 'public_key = {}'.format(public_key)
                    client.send(pesan.encode('ascii')) 
                print(message)

            elif ":" in message:
                rkb_rev = rkb[::-1]
                rk_rev = rk[::-1]
                
                # rev_rkb = rev_rkb.reverse()
                # print(rkb)
                # decoded_msg=''
                temp = message
                part = temp.split(": ",1)
                part2 = part[1].split('with encoded key: ',1)
                
                    # print("cipher blok")
                print(part2[1])
                decoded_des_key = decoder(int(part2[1]),secret_key)
                # decoded_des_key = decoder(part2[1],secret_key)
                
                # rk,rkb = round(decoded_des_key)
                # cipher_blok = hex_to_string(bin2hex(encrypt(part[1], rkb_rev, rk_rev)))
                # temp = '{}: {}'.format(part[0], cipher_blok)
                print(decoded_des_key)

            
            else:
                # part = message.split("\n",1)
                print(message)
        except:
            # Close Connection When Error
            
            print()
            client.close()
            break

# Sending Messages To Server
def write():
    global client
    encoded_message = ''
    try:
        while True:
            try:
                kirim = input()
                kemana = 'penerima = {}'.format(kirim)
                client.send(kemana.encode('ascii'))
                user_inp = input()
                if user_inp == "END" or kirim == "END":
                    client.close()
                    print("Koneksi ditutup oleh pengguna.")
                    break
                message_blok = split_into_blocks(user_inp)
                for blok in message_blok:
                    blok = pad_input(blok)
                    cipher_blok = des_encrypt_block(blok, rkb, rk)
                    encoded_message += cipher_blok
                encoded_des_key = encoder(keyraw,public_key)
                message = '{}: {} with encoded key: {}'.format(nickname, encoded_message,encoded_des_key)
                # print(encoded_des_key)
                client.send(message.encode('ascii'))
                encoded_message = ''
            except EOFError:
                print("EOFError: Input dihentikan.")
                break
    except Exception as e:
        print(f"Error dalam thread write: {e}")
    finally:
        client.close()

# Starting Threads For Listening And Writing
receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()

receive_thread.join()
write_thread.join()