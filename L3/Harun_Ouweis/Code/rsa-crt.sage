from hashlib import sha256

def key_gen():
    phi = 2
    e = 2
    while gcd(phi, e) != 1 : 
        p = random_prime(2**1024, proof = False)
        q = random_prime(2**1024, proof = False)
        n = p*q
        phi = (p-1) * (q-1)
        e = 65537
    d = inverse_mod(e, phi)
    return (e, d, n, p, q)

def sign(m, d, p, q, n):
    dp = d % (p-1)
    dq = d % (q-1)
    h = int.from_bytes(sha256(m).digest(), byteorder = "big")
    #Nous introduisons ici le bug
    sp = ZZ.random_element(p)# Nous simulons ici le bug. Vrai code: power_mod(h, dp, p)
    sq = power_mod(h, dq, q)
    return crt([sp, sq], [p, q])

# Crée une signature RSA-CRT correcte pour le message donné.
def correct_sign(m, d, p, q, n):
    dp = d % (p - 1)
    dq = d % (q - 1)
    h = int.from_bytes(sha256(m).digest(), byteorder="big")
    sp = power_mod(h, dp, p)
    sq = power_mod(h, dq, q)
    # Combinaison des résultats corrects de sp et sq
    return crt([sp, sq], [p, q])

# Valide une signature donnée pour un message et une clé publique.
def validate_sign(m, s, e, n):
    h = int.from_bytes(sha256(m).digest(), byteorder="big")
    m_prime = power_mod(s, e, n)
    # Vérifie si le message déchiffré est égal au hachage du message original
    return m_prime == h

# Récupère la clé privée (p, q, d) à partir de la clé publique et d'une signature buggée.
def recover_key(e, n, m, s):
    h = int.from_bytes(sha256(m).digest(), byteorder="big")
    m_prime = power_mod(s, e, n)
    
    # Calcul de p en utilisant le PGCD entre (h - m') et n
    p = gcd(h - m_prime, n)
    if p == 1 or p == n:
        raise ValueError("Failed to factorize n using the provided signature.")
    q = n // p
    # Calcul de d, l'inverse de e mod (p-1)*(q-1)
    d = power_mod(e, -1, (p - 1) * (q - 1))
    
    return (p, q, d)

# Teste la clé privée trouvée en signant à nouveau le message et en validant la signature.
def test_recovered_key(m, p, q, d, e, n):
    test_signature = correct_sign(m, d, p, q, n)
    if validate_sign(m, test_signature, e, n):
        print("Signature correcte avec la clé privée récupérée.")
    else:
        print("Échec de la validation de la signature avec la clé privée récupérée.")

def generate():
    (e, d, n, p, q) = key_gen()
    m = b"This message is signed with RSA-CRT!"
    s = sign(m, d, p, q, n)
    print("e = %s" % str(e))
    print("n = %s" % str(n))
    print("s = %s" % s)

    (p, q, d) = recover_key(e, n, m, s)
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"d = {d}")
    
    test_recovered_key(m, p, q, d, e, n)

# Teste la fonction de récupération de la clé privée avec les paramètres fournis.
def test_recover_key():
    e = 65537
    n = 2764878579367236427928738971333498145805735593896776311923898023302719184366477166557094971638253966594648081027245336021264787084496036955160325092633888534918878533993606377235339046425976776098363512005112029886626154775822348317667151303697216785995525381855239442885439785205051585408650470555364577635388721585216694154051253851086752997320940607305332466155257671125306591470611383608361894247048640165897750470818561690266571095879463360976621720823812562615137773189782844720032216519835031125337060547869875995084135889587519127406713424853647593284536412736127787204835868895292587843631178920662849262627
    m = b'This message is signed with RSA-CRT!'
    s = 732816077420210106609056863861895722138193426892543394135902737531996429590992864953651840420295513159702699472922336519542471863019522949645591237926641904642109548554728323781076013410040273127294392913941057613671285302687420071217244949033738547719898663045862767361400002113524853705450175579080956755677903661313562308673250792708759148329503024342787132632945009572205330407763411727115610670808582306208667993356339760397616377042016849956277539888067728900013169560184754106524106331889136339314602387548747717209815047883365297761118316220829389763006353327133509880775029105113466788085025292179988735795

    (p, q, d) = recover_key(e, n, m, s)
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"d = {d}")
    
    test_recovered_key(m, p, q, d, e, n)

# Exécution du test avec génération des clés et des signatures
generate()
print("Génération et test de hack terminés.\n\n\n")
test_recover_key()
print("Test de hack avec les paramètres fournis terminé.")
