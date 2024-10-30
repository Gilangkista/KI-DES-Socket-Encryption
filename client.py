import socket
from DES import string_to_hex, hex2bin, bin2hex, encrypt, shift_left, permute, pad_input

def main():
    host = 'localhost'
    port = 12345

    pt = input("Enter the plain text: ")
    pt = pad_input(pt)
    temp = string_to_hex(pt)
    print("In hex:", temp)

    input_key = input("Enter the key: ")
    key = string_to_hex(input_key)
    key = hex2bin(key)

    # Number of bit shifts
    shift_table = [1, 1, 2, 2,
                   2, 2, 2, 2,
                   1, 2, 2, 2,
                   2, 2, 2, 1]

    # Key Compression Table: Compression of key from 56 bits to 48 bits
    key_comp = [14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32]

    # Splitting
    left = key[0:28]  
    right = key[28:56]  # Lahan kunci kanan

    #ROUND KEYS binary and hexa
    rkb = []  
    rk = []   

    for i in range(0, 16):
        # Shifting the bits by nth shifts by checking from shift table
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])

        combine_str = left + right

        # Compression of key from 56 to 48 bits
        round_key = permute(combine_str, key_comp, 48)

        rkb.append(round_key)
        rk.append(bin2hex(round_key))

    print("Encryption")
    cipher_text = bin2hex(encrypt(temp, rkb, rk))
    print("Cipher Text:", cipher_text)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print("Connected to server.")

        # Kirim cipher text
        s.sendall(cipher_text.encode())
        print("Sent Cipher Text:", cipher_text)

        # Gabungkan rkb dan rk jadi satu string 
        round_keys_data = f"{str(rkb)}|{str(rk)}"
        s.sendall(round_keys_data.encode())  # Kirim sebagai string
        print("Sent Round Keys.")

if __name__ == "__main__":
    main()
