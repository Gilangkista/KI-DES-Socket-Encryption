import random
import math

# A set will be the collection of prime numbers,
# where we can select random primes p and q

public_key = None
private_key = None
n = None

# We will run the function only once to fill the set of
# prime numbers
def primefiller(prime):
    # Method used to fill the primes set is Sieve of
    # Eratosthenes (a method to collect prime numbers)
    seive = [True] * 250
    seive[0] = False
    seive[1] = False
    for i in range(2, 250):
        for j in range(i * 2, 250, i):
            seive[j] = False

    # Filling the prime numbers
    for i in range(len(seive)):
        if seive[i]:
            prime.add(i)
    return prime


# Picking a random prime number and erasing that prime
# number from list because p!=q
def pickrandomprime(prime):
    k = random.randint(0, len(prime) - 1)
    it = iter(prime)
    for _ in range(k):
        next(it)

    ret = next(it)
    prime.remove(ret)
    return ret


def setkeys(prime):
    # global public_key, private_key, n
    prime1 = pickrandomprime(prime)  # First prime number
    prime2 = pickrandomprime(prime)  # Second prime number
    print(prime1,prime2)

    global n
    n = prime1 * prime2
    fi = (prime1 - 1) * (prime2 - 1)

    e = 2
    while True:
        if math.gcd(e, fi) == 1:
            break
        e += 1

    # d = (k*Φ(n) + 1) / e for some integer k
    public_key = e

    d = 2
    while True:
        if (d * e) % fi == 1:
            break
        d += 1

    private_key = d
    return public_key,private_key


# To encrypt the given number
def encrypt(message,public_key):
    global n
    e = public_key
    encrypted_text = 1
    while e > 0:
        encrypted_text *= message
        encrypted_text %= n
        e -= 1
    return encrypted_text


# To decrypt the given number
def decrypt(encrypted_text,private_key):
    global n
    d = private_key
    decrypted = 1
    while d > 0:
        decrypted *= encrypted_text
        decrypted %= n
        d -= 1
    return decrypted


# First converting each character to its ASCII value and
# then encoding it then decoding the number to get the
# ASCII and converting it to character
def encoder(message,public_key):
    encoded = []
    # Calling the encrypting function in encoding function
    for letter in message:
        encoded.append(encrypt(ord(letter),public_key))
    return encoded


def decoder(encoded,private_key):
    s = ''
    # Calling the decrypting function decoding function
    for num in (encoded):
        s += chr(decrypt(num),private_key)
    return s
