from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature.pss import MGF1
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.strxor import strxor
from Crypto.Math.Numbers import Integer

MODULE_SIZE = 256 # in bytes
HASH_SIZE = 32 # in bytes
MAX_MESSAGE_SIZE = 221 # in bytes
SEED_SIZE = MODULE_SIZE - HASH_SIZE - MAX_MESSAGE_SIZE - 2 # -2 for the 0x01 in padding and the 0x00 in schema

def key_gen():
    phi = 2
    e = 2
    while gcd(phi, e) != 1:
        p = random_prime(2**1024)
        q = random_prime(2**1024)
        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537
    d = inverse_mod(e, phi)
    return (int(e), int(d), int(n))

HL = SHA256.new(data=b"").digest() # Constant for padding

def mgf(seed, length):
    # This function is correct and you don't need to look at it
    return MGF1(seed, length, SHA256)

def encrypt_OAEP(m, e, n):
    if len(m) > MAX_MESSAGE_SIZE:
        raise ValueError("Message too large")
    # Pad message
    zeros = b"\x00" * (MODULE_SIZE - HASH_SIZE - SEED_SIZE - len(m) - 2)
    padded_m = HL + zeros + b"\x01" + m
    seed = get_random_bytes(SEED_SIZE)
    masked_DB = strxor(padded_m, mgf(seed, len(padded_m)))
    masked_seed = strxor(seed, mgf(masked_DB, len(seed)))
    to_encrypt = int.from_bytes(masked_seed + masked_DB, byteorder="big")
    # Textbook RSA
    return power_mod(to_encrypt, e, n)

def textbook_rsa_decrypt(c, d, n):
    # Déchiffrement RSA classique
    return int(power_mod(c, d, n)).to_bytes(MODULE_SIZE, byteorder="big")

def unpad(message):
    # Retirer le padding du message
    index = message.find(b'\x01', HASH_SIZE)
    if index == -1:
        raise ValueError("Padding incorrect")
    return message[index + 1:]

def decrypt_OAEP(c, d, n):
    # Déchiffrement RSA classique
    masked_message = textbook_rsa_decrypt(c, d, n)
    
    # Extraction de masked_seed et masked_DB
    masked_seed = masked_message[1:SEED_SIZE + 1]
    masked_DB = masked_message[SEED_SIZE + 1:]
    
    # Récupération du seed original
    seed = strxor(masked_seed, mgf(masked_DB, len(masked_seed)))
    
    # Récupération du DB original
    DB = strxor(masked_DB, mgf(seed, len(masked_DB)))
    
    # Retirer le padding et retourner le message déchiffré
    return unpad(DB)

# Nouvelle implémentation avec pycryptodome
def encrypt_OAEP_pycryptodome(message, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message)
    return ciphertext

def decrypt_OAEP_pycryptodome(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    message = cipher.decrypt(ciphertext)
    return message

# Fonction de test pour vérifier les déchiffrements
def test_decrypt_OAEP():
    (e, d, n) = key_gen()
    message = b"Bonjour, ceci est un test."

    # Clé RSA pour pycryptodome
    private_key = RSA.construct((n, e, d))
    public_key = private_key.publickey()
    
    # Chiffrement et déchiffrement avec l'ancienne implémentation
    ciphertext_old = encrypt_OAEP(message, e, n)
    decrypted_message_old = decrypt_OAEP(ciphertext_old, d, n)
    
    assert decrypted_message_old == message, "Le message déchiffré ne correspond pas au message original avec l'ancienne implémentation."
    print("Test réussi : Le message a été déchiffré correctement avec l'ancienne implémentation.")
    
    # Chiffrement et déchiffrement avec la nouvelle implémentation
    ciphertext_new = encrypt_OAEP_pycryptodome(message, public_key)
    decrypted_message_new = decrypt_OAEP_pycryptodome(ciphertext_new, private_key)
    
    assert decrypted_message_new == message, "Le message déchiffré ne correspond pas au message original avec la nouvelle implémentation."
    print("Test réussi : Le message a été déchiffré correctement avec la nouvelle implémentation.")

# Fonction pour simuler le chiffrement RSA avec un seed spécifique
def simulate_RSA_OAEP_encryption(message, public_exponent, modulus, seed_value):
    # Convertir la valeur du seed en octets
    seed_in_bytes = seed_value.to_bytes(1, byteorder="big")
    
    # Vérifier la taille du message
    if len(message) > MAX_MESSAGE_SIZE:
        raise ValueError("Message trop long")

    # Appliquer le padding au message
    zero_padding = b"\x00" * (MODULE_SIZE - HASH_SIZE - SEED_SIZE - len(message) - 2)
    padded_message = HL + zero_padding + b"\x01" + message
    
    # Masquer les données DB
    masked_DB = strxor(padded_message, mgf(seed_in_bytes, len(padded_message)))
    masked_seed = strxor(seed_in_bytes, mgf(masked_DB, len(seed_in_bytes)))
    
    # Convertir les données masquées en entier pour le chiffrement RSA
    integer_representation = int.from_bytes(masked_seed + masked_DB, byteorder="big")
    
    # Chiffrement RSA classique
    return power_mod(integer_representation, public_exponent, modulus)

# Attaque par force brute pour retrouver la note chiffrée
def bruteforce_decryption(ciphertext, public_exponent, modulus):
    # Parcourir toutes les valeurs possibles de seed et de note
    for seed in range(256):
        for decimal_part in range(61):
            # Générer la note à tester
            test_note = round(decimal_part * 0.1, 1)
            note_bytes = str(test_note).encode()
            
            try:
                # Simuler le chiffrement avec la note et le seed actuels
                potential_ciphertext = simulate_RSA_OAEP_encryption(note_bytes, public_exponent, modulus, seed)
                # Vérifier si le texte chiffré correspond
                if ciphertext == potential_ciphertext:
                    return test_note
            except ValueError:
                continue

def test_attack():
    e = 65537
    n = 6812235255033480911590722368648599426912660957511884853094129190267647163384364667606816602914138933099308876261214557528105932555072775861086080237272697177626430650063944721690854013992864647927665942471911243542562280512028474832704811069877553294225228929722966399724774953520155705135783304698283958025774978181524640224725768916481123650037849962797575081336444457589996758002300665032930138450150239381413952404564905268260618499824385259563415538339629704423382931295772361631164242288257581914337254528619389832704926708427530763032864938488463108333636495117355857734494284248390512376115168491620045783723
    c = 4749126886757330400663174443411666284111808319347373486831002632627986584499797011388865974459050463059935946014864266699226573523682575693465085016649490417324041945606573870414350884063065371751689187128301196717101359196254503408327885622496474077752604124722881613194977743571896898265259426053118149459224398847081997629502114200177725249202706037017983078786433506582499664444311071631616698208291485805510874263048161602533348076102167726982069178965241045463958297566381194058822067019368122271830630889343637840566332914863770119985880311580910090600715075811444967670090964213193083623893521951806826904832

    # Attaque par force brute pour retrouver la note
    found_note = bruteforce_decryption(c, e, n)

    if found_note:
        print(f"La note retrouvée du collègue est : {found_note}")
    else:
        print("L'attaque n'a pas réussi à retrouver la note correcte.")

# Exécution des tests
test_decrypt_OAEP()
print("test_decrypt_OAEP est terminé. \n")
test_attack()
print("test_attack est terminé.")
