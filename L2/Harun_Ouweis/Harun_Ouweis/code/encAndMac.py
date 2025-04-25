from Crypto.Cipher import AES
from base64 import b64decode


NONCE_LENGTH = 12
p = 340282366920938463463374607431768211507 #prime number


def bytesToInt(message):
    return int.from_bytes(message, "big")

def intToBytes(i):
    return int(i).to_bytes(16, "big")

def modInverse(a, p):
    """Calculer l'inverse modulaire de a modulo p."""
    return pow(a, p - 2, p)



#Compute the mac of message under key with nonce. 
#It is similar to Poly1305
def mac(nonce, message, key):
    cipher = AES.new(key, mode = AES.MODE_ECB)
    v = bytesToInt(cipher.encrypt(b"\xff"*16))
    blocks = [message[i:i+16] for i in range(0,len(message),16)]
    temp = 0
    for b in blocks:
        temp = (temp + bytesToInt(b)*v) % p
    temp = (temp + bytesToInt(cipher.encrypt(nonce + b"\x00"*(16-NONCE_LENGTH)))) % p
    return intToBytes(temp)
    
#Encrypts the message under key with nonce. 
#It is an improved CTR that exploits the power of prime numbers
def encrypt(nonce, message, key):
    ct = b""
    for i in range(len(message)//16):
        cipher = AES.new(key, mode = AES.MODE_CTR, nonce = nonce)
        keystream = cipher.encrypt(b"\x00"*16) #Way to obtain keystream: we XOR with 0
        temp = (bytesToInt(message[16*i:16*(i+1)]) + bytesToInt(keystream)) % p
        ct += intToBytes(temp)
    return ct


#Encrypt and MAC with the fixed algorithm
def encryptAndMac(nonce, message, key):
    ct = encrypt(nonce, message, key)
    tag = mac(nonce, message, key)
    return (ct, tag)


def calculate_sigma(c_block, m_block):
    """Calculer sigma pour un bloc de texte chiffré et son bloc de texte clair correspondant."""
    return (bytesToInt(c_block) - bytesToInt(m_block)) % p

def calculate_v(tag, sigma, sumM):
    """Calculer la constante v."""
    return ((bytesToInt(tag) - sigma) * modInverse(sumM, p)) % p

def sum_blocks(blocks):
    """Calculer la somme d'une liste de blocs de 128 bits."""
    return sum([bytesToInt(block) for block in blocks]) % p

def decrypt(nonce, ciphertext, v, sigma):
    """Déchiffrer un texte chiffré en utilisant une constante v, un nonce, et sigma."""
    blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
    plaintext = b""

    for i, block in enumerate(blocks):
        block_value = (bytesToInt(block) - sigma) % p
        plaintext += intToBytes(block_value)
    
    return plaintext

def attack(m1, nonce1, tag1, c1, nonce2, tag2, c2):
    """Casser le chiffrement d'un deuxième message en utilisant des informations du premier."""

    # Décodage des données de base64
    c1 = b64decode(c1)
    c2 = b64decode(c2)
    tag1 = b64decode(tag1)
    tag2 = b64decode(tag2)

    # Diviser les messages et textes chiffrés en blocs
    m1_blocks = [m1[i:i + 16] for i in range(0, len(m1), 16)]
    c1_blocks = [c1[i:i + 16] for i in range(0, len(c1), 16)]
    c2_blocks = [c2[i:i + 16] for i in range(0, len(c2), 16)]

    # Calculer sigma pour le premier message
    sigma = calculate_sigma(c1_blocks[0], m1_blocks[0])

    # Sommes des blocs
    sumM1 = sum_blocks(m1_blocks)
    sumC2 = sum_blocks(c2_blocks)

    # Calculer v
    v = calculate_v(tag1, sigma, sumM1)

    # Trouver sigma pour le deuxième message
    n = len(c2_blocks)
    sigma2 = (bytesToInt(tag2) - v * sumC2) * modInverse(1 - v * n, p) % p

    # Déchiffrer le deuxième message
    plaintext2 = decrypt(nonce2, c2, v, sigma2)
    
    print("Texte clair 2 =", plaintext2)
    return plaintext2

def test():
    m1 = b'ICRYInTheMorning'
    nonce1 = b'mgoa0tf7LjIT9rV0'
    c1 = b'A/Ct+UCiy0ZPco4nuEvQ8g=='
    tag1 = b'9au/PD0YY9iBGbvipVSeaw=='
    nonce2 = b'DOOzsUSa8hkl6QX5'
    c2 = b'ELRHflKFADumPOGocKJ7RTC3PosAjP7o5oj5tX3rdkc='
    tag2 = b'pDc+m8H73drtkK0zlK4O+Q=='


    print("Cassage du chiffrement du deuxième message")
    attack(m1, nonce1, tag1, c1, nonce2, tag2, c2)

test()


