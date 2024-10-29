# des.py
def string_to_hex(s):
    return ''.join([hex(ord(c))[2:].zfill(2).upper() for c in s])

def hex2bin(s):
    mp = {'0': "0000", '1': "0001", '2': "0010", '3': "0011", '4': "0100", '5': "0101", 
          '6': "0110", '7': "0111", '8': "1000", '9': "1001", 'A': "1010", 
          'B': "1011", 'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"}
    return ''.join(mp[c] for c in s)

def bin2hex(s):
    mp = {"0000": '0', "0001": '1', "0010": '2', "0011": '3', "0100": '4', 
          "0101": '5', "0110": '6', "0111": '7', "1000": '8', "1001": '9', 
          "1010": 'A', "1011": 'B', "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'}
    return ''.join(mp[s[i:i + 4]] for i in range(0, len(s), 4))

def xor(a, b):
    return ''.join('0' if x == y else '1' for x, y in zip(a, b))

def pad(text):
    pad_len = 8 - (len(text) % 8)  
    return text + chr(pad_len) * pad_len

def unpad(text):
    pad_len = ord(text[-1])
    return text[:-pad_len]

def encrypt(plain_text, key):
    padded_text = pad(plain_text)
    encrypted = ""
    
    for i in range(0, len(padded_text), 8):
        block = padded_text[i:i + 8]
        binary = hex2bin(string_to_hex(block))
        encrypted_block = xor(binary, key * (len(binary) // len(key)))
        encrypted += bin2hex(encrypted_block)
    
    return encrypted

def decrypt(cipher_text, key):
    decrypted = ""
    
    for i in range(0, len(cipher_text), 16):
        block = cipher_text[i:i + 16]
        binary = hex2bin(block)
        decrypted_block = xor(binary, key * (len(binary) // len(key)))
        hex_str = bin2hex(decrypted_block)
        decrypted += bytes.fromhex(hex_str).decode('utf-8')
    
    return unpad(decrypted)
