from Crypto.Cipher import AES
from Crypto import Random
from base64 import b64encode, b64decode
from Crypto.Util.strxor import strxor
import sys


def pad(m):
    m += b"\x80"
    while len(m) % 16 != 0:
        m+= b"\x00"
    return m

def h(m, k):
    m = pad(m)
    blocks = [m[i:i + 16] for i in range(0, len(m), 16)]
    h = k
    for i in range(len(blocks)):
        h = strxor(AES.new(blocks[i], AES.MODE_ECB).encrypt(h), h)
    return h

def mac(message, key):
    return h(message, key)

def verify(message, key, tag):
    return mac(message, key) == tag

def create_prime_message(m, previous_mac, new_amount):
    # Remplir le message original et ajouter le nouveau montant
    m_prime = pad(m) + new_amount

    # Calculer le nouveau MAC en utilisant la fonction h
    new_mac = h(new_amount, previous_mac)

    return new_mac, m_prime


def ex():
    k = Random.get_random_bytes(16)
    m = b"Sender: Alexandre Duc; Destination account 12-1234-12. Amount CHF123"
    mc = mac(m, k)
    print("keyMac = %s" % b64encode(k), file=sys.stderr)
    print("m = %s" % m)
    print("mac = %s" % b64encode(mc))

    # Message falsifié
    new_amount = b"123456"
    forged_mac, forged_message = create_prime_message(m, mc, new_amount)

    # Vérification du message original avec la clé
    verification_original = verify(m, k, mc)
    print("Verification of original message with key = %s" % verification_original)

    # Vérification du message falsifié avec la clé originale
    verification_forged = verify(forged_message, k, forged_mac)
    print("Verification of forged message with original key = %s" % verification_forged)

    # Affichage des résultats
    print("Forged message:")
    pretty_print(forged_message)
    print("Original MAC = %s" % b64encode(mc))
    print("Forged MAC = %s" % b64encode(forged_mac))

    # Données fournies dans Harun_Ouweis-parameters.txt
    provided_message = b"Sender: Alexandre Duc; Destination account 12-1234-12. Amount CHF123"
    provided_mac = b'yZWqJpCxqU70zCSDLrl/PA=='

    # Convertir le MAC base64 en bytes
    provided_mac_bytes = b64decode(provided_mac)

    # Créer un message falsifié avec la donnée fournie
    forged_mac_provided, forged_message_provided = create_prime_message(provided_message, provided_mac_bytes, new_amount)

    # Vérifier la validité du message fourni
    print("Provided message = %s" % provided_message)
    print("Provided MAC = %s" % provided_mac)
    print("Verification of forged message with my key = %s" % verify(forged_message_provided, k, forged_mac_provided)) # doit retourner False


    # Affichage du message falsifié
    print("Forged message for provided message:")
    pretty_print(forged_message_provided)


#m has to be a bytestring
def pretty_print(m):
    print(m.decode("UTF-8", errors="ignore"))

ex()