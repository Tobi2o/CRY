from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
def encrypt(message, key):
    #pad the message
    message = pad(message, 16)
    
    cipher = AES.new(key, mode = AES.MODE_ECB)
    
    IV = Random.get_random_bytes(16)

    ciphertext= [IV]
    #First block
    m1 = message[:16]
    t = cipher.encrypt(m1)
    c1 = strxor(t, IV)
    ciphertext.append(c1)
    #Remaining blocks don't have an IV
    message_blocks = [message[16*(i+1):16*(i+2)] for i in range(len(message)//16-1)]
    for m in message_blocks:
        t = cipher.encrypt(t)
        c = strxor(t, m)
        ciphertext.append(c)

    return b"".join(ciphertext)


def decrypt(ciphertext, key):
    """Déchiffre un texte chiffré en utilisant une clé donnée."""
    cipher = AES.new(key, AES.MODE_ECB)
    IV = ciphertext[:16]  # Récupère l'IV du texte chiffré.

    # Divise le texte chiffré en blocs
    blocks = split_into_blocks(ciphertext)

    # Déchiffre les blocs
    decrypted_message = decrypt_blocks(cipher, blocks, IV)

    return unpad(decrypted_message, 16)  # Supprime le padding du message décrypté.

def split_into_blocks(data, block_size=16):
    """Divise les données en blocs de la taille spécifiée."""
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]

def decrypt_blocks(cipher, blocks, initial_vector):
    """Déchiffre tous les blocs en utilisant un flux de clé."""
    decrypted_message = []

    # Déchiffre le premier bloc
    t = strxor(blocks[1], initial_vector)
    decrypted_message.append(cipher.decrypt(t))

    # Déchiffre les blocs suivants
    for i in range(2, len(blocks)):
        t = cipher.encrypt(t)
        m = strxor(blocks[i], t)
        decrypted_message.append(m)

    return b"".join(decrypted_message)

def crack(m1, c1, c2):
    """Casse le chiffrement en comparant les flux de clé et décrypte c2."""
    m1 = pad(m1, 16)
    m1_blocks = split_into_blocks(m1)
    c1_blocks = split_into_blocks(c1)
    c2_blocks = split_into_blocks(c2)

    # Compare les flux de clé
    t_1 = strxor(c1_blocks[1], c1_blocks[0])
    t_2 = strxor(c2_blocks[1], c2_blocks[0])

    if t_1 == t_2:
        m2_blocks = [m1_blocks[0]]
        c1_blocks, c2_blocks, m1_blocks = c1_blocks[2:], c2_blocks[2:], m1_blocks[1:]

        t_blocks = []

        # Décrypte chaque bloc et ajoute-le à t_blocks
        for index, c1_block in enumerate(c1_blocks):
            m1_block = m1_blocks[index]
            t_block = strxor(c1_block, m1_block)
            t_blocks.append(t_block)

        # Utilise t_blocks pour décrypter c2_blocks et ajoute-le à m2_blocks
        for index, c2_block in enumerate(c2_blocks):
            m2_block = strxor(t_blocks[index], c2_block)
            m2_blocks.append(m2_block)

        return b"".join(m2_blocks)

def test():
    key = Random.get_random_bytes(16)
    m1 = b"This is a long enough test message to check that everything is working fine and it does. This algorithm is super secure and we will try to sell it soon to the Swiss governement."

    print("Message clair initial:", m1)

    c1 = encrypt(m1, key)
    print("Texte chiffré (c1):", b64encode(c1))

    print("Message décrypté:", decrypt(c1, key))

    c1 = b'XOgSrKCoHUuR60z2GUzD26Y4QQafHkIE877ZekY4HNE59NFKnETUHguGeiyTQJ0oXl0oOLSQVbYvAoLKgzaATB2CRnB4VMLzHLhyvUq5T5bSVplRx7t4s/mYPPSOjrxtZs9eQ8AwxJtgr4K3RKs2Qw+AerohzyDqEj35mUwCiDWvQ1cWRqeZJheZEdYUeT6YCs+iLl5TRqBo61VdmXxkpxRoi0TOdg7rvys3YwmIyF/k7D6jDT7f8u7QSkJekeGh+9A3DLuIzjVMvOZLhya3TQ=='
    c2 = b'FXQa4Ea1GkOBt4yTWLM1wO+kSUp5A0UM4+IZHwfH6so59NFKnETNHguBOyaTE4gmSxhhOPvEWf4oBMmZkj2USljJEEFiSJboELVn+FfqCY3cQ9JR2vw1sPyXN7OKk9pP'
    c1_decoded = b64decode(c1)
    c2_decoded = b64decode(c2)

    plaintext = crack(m1, c1_decoded, c2_decoded)

    print("C2 décrypté:", plaintext)


test()

