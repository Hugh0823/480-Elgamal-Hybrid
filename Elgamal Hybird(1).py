import numpy as np
import random
import sys
import base64
from Crypto.Cipher import AES
from Crypto import Random
from scipy.linalg import solve


# Pad data for aes encryption
def pad(s):
    BS = AES.block_size
    return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)


# Unpad data
def unpad(s):
    BS = AES.block_size
    return s[:-ord(s[len(s)-1:])]


# AES encryption
def aes_encrypt(key, raw):
    raw = base64.b64encode(pad(raw).encode('utf8'))
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))


# AES decryption
def aes_decrypt(key, enc):
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    return unpad(base64.b64decode(cipher.decrypt(enc[AES.block_size:])).decode('utf8'))


def power(g, b, p):
    x = 1
    y = g

    while b > 0:
        if b % 2 != 0:
            x = (x * y) % p;
        y = (y * y) % p
        b = b // 2

    return x % p


# create a polynomial function
def create_f(coeffs, s):
    def f(x):
        degree = len(coeffs)
        result =  0
        for coeff in coeffs:
            result += coeff * x**degree
            degree -= 1
        return result + s
    return f

# generate random polynomial function
"""
t: threshold
s: secrte 
"""
def random_poly(t, s):
    coeffs = [random.randint(1, 100) for i in range(t)] # random coefficients
    return create_f(coeffs, s)


"""
Distributed keys generator
t: threshold
n: number of keys generated
s: secret
"""
def generate_distributed_keys(t, n, s, g, p):
    if t >= n:
        raise Exception("n must be larger than t.")
    if t <= 0:
        raise Exception("t must be positive.")
    f = random_poly(t, s) # generate a random polynomial function
    PK = []
    SK = []
    #j = 0
    for i in range(n):
        x = random.randint(-n*3, n*3)
        while f(x) <= 0:
            x = random.randint(-n*3, n*3)
        mod = power(g, f(x), p)
        while x == 0 or mod in PK:
            x = random.randint(-n*3, n*3)
            mod = power(g, f(x), p)
            #print(j)
            #j += 1
        SK.append((x, f(x), mod))
        PK.append(mod)
    return SK, PK


# get the corresponding secret key for the public key
def get_pair(SK, key):
    for pair in SK:
        if key == pair[2]:
            return pair
    raise Exception("The key is wrong.")


"""
get secret from distributed kwys
PK: list of distributed keys
t: threshold
"""
def get_secret(SK, keys, t, g, p):
    if len(keys) <= t:
        raise Exception("At least one key is wrong.")
    for key in keys:
        if key not in PK:
            raise Exception("At least one key is wrong.")
    V = np.ones((t+1, t+1), dtype=float)
    B = np.zeros((t+1, 1), dtype=float)
    for i in range(t+1):
        secret_pair = get_pair(SK, keys[i])
        for j in range(1, t+1):
            #k = PK.index(keys[i])
            V[i][j] = secret_pair[0]**j
        B[i] = secret_pair[1]
    """
    V_invse = np.linalg.inv(V)
    secr = int(round(np.matmul(V_invse[0], B)[0]))
    """
    x = solve(V, B)
    secr = int(round(x[0][0]))
    return secr, power(g, secr, p)


def encrypt(msg, t, n, g, g_a, p):
    #en_msg = []
    b = random.randint(1, 30)  # Private key for sender
    #print("b:", b)
    s = power(g_a, b, p)
    """
    for i in range(0, len(msg)):
        en_msg.append(msg[i])

    for i in range(0, len(en_msg)):
        en_msg[i] = s * ord(en_msg[i])
    """
    aes_key = Random.new().read(32)
    AES_en_msg = aes_encrypt(aes_key, msg)
    int_enc = int.from_bytes(AES_en_msg, "big") #convert aes encrypted message to interge
    #print(int_enc)
    #print(int_enc.bit_length())
    en_msg = int_enc * s
    ##hybird_en_msg = int_enc * s
    #en_msg = hybird_en_msg.to_bytes((hybird_en_msg.bit_length()+7)//8, "big")
    SK, PK = generate_distributed_keys(t, n, b, g, p)
    SK.append(aes_key)
    return en_msg, SK, PK


def decrypt(en_msg, SK, keys, a, t, g, p):
    #dr_msg = []
    b, g_b = get_secret(SK, keys, t, g, p)
    #print("Decode b:", b)
    h = power(g_b, a, p)
    """
    for i in range(0, len(en_msg)):
        dr_msg.append(chr(int(en_msg[i] / h)))
    """
    aes_key = SK[-1]
    #en_msg = int.from_bytes(en_msg, "big")
    aes_en_msg = en_msg // h
    #print(aes_en_msg)
    #print(aes_en_msg.bit_length())
    aes_en_msg = aes_en_msg.to_bytes((aes_en_msg.bit_length()+7)//8, "big") # convert to bytes
    dr_msg = aes_decrypt(aes_key, aes_en_msg)
    return dr_msg

# Generate the large  number for P.
def Generate_p():
    temp = random.randint(pow(2,2000), pow(2,2100))
    return temp

def Generate_g(p):
    while True:
        q = random.randint(pow(2,2000),pow(2,2100))
        h = random.randint(2,p-1)
        g = power(h,(p-1)//q,p)
        if(g != 1):
            break
    return g

## check if p is prime
def is_Prime(n,k=5):
    from random import randint
    if n < 2: return False
    for p in [2,3,5,7,11,13,17,19,23,29]:
        if n % p == 0: return n == p
    s, d = 0, n-1
    while d % 2 == 0:
        s, d = s+1, d//2
    for i in range(k):
        x = pow(randint(2, n-1), d, n)
        if x == 1 or x == n-1: continue
        for r in range(1, s):
            x = (x * x) % n
            if x == 1: return False
            if x == n-1: break
        else: return False
    return True


if __name__ == "__main__":
    t = 8
    n = 12
    p = Generate_p()
    while(is_Prime(p) != True):
        p = Generate_p()
    g = Generate_g(p)
    a = random.randint(0, 10)
    g_a = power(g, a, p)
    #print("a:", a)
    msg = "Hello World, this is my elgamal, threshold, AES hybird encryption algorithm."
    print("PlainText:", msg)
    en_msg, SK, PK = encrypt(msg, t, n, g, g_a, p)
    print("CipherText:", en_msg)
    print("Public keys:",PK)
    de_msg = decrypt(en_msg, SK, PK[1:t+2], a, t, g, p)
    print("Decrypted Message:", de_msg)
