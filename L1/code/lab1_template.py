
# IMPORTANT
# IL EST PRIMORDIAL DE NE PAS CHANGER LA SIGNATURE DES FONCTIONS
# SINON LES CORRECTIONS RISQUENT DE NE PAS FONCTIONNER CORRECTEMENT

from statistics import mean
import unicodedata

NB_LETTERS = 26
LETTER_A = ord('A')
MAX_KEY_LENGTH = 20

def caesar_encrypt(text, key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    key: the shift which is a number

    Returns
    -------
    the ciphertext of <text> encrypted with Caesar under key <key>
    """
    text = clean_text(text)

    if not text:
        return text

    encrypted_text = []
    for char in text:
        # Calculer le décalage de la lettre
        shifted_index = (ord(char) - LETTER_A + key) % NB_LETTERS
        encrypted_text.append(chr(shifted_index + LETTER_A))
    return ''.join(encrypted_text)


def caesar_decrypt(text, key):
    """
    Parameters
    ----------
    text: the ciphertext to decrypt
    key: the shift which is a number

    Returns
    -------
    the plaintext of <text> decrypted with Caesar under key <key>
    """

    text = clean_text(text)
    if not text:
        return text
    
    # Utiliser la fonction de chiffrement avec un décalage inverse pour déchiffrer
    # En python cela ne pose pas de problème
    return caesar_encrypt(text, -key % NB_LETTERS)


def freq_analysis(text):
    """
    Parameters
    ----------
    text: the text to analyse

    Returns
    -------
    list
        the frequencies of every letter (a-z) in the text.

    """
    text = clean_text(text)
    if not text:
        return [0] * 26    
    
    # Each value in the vector should be in the range [0, 1]
    freq_vector = [0] * 26
    for char in text:
        if char.isalpha():
            index = ord(char) - LETTER_A
            if 0 <= index < 26:
                freq_vector[index] += 1

    total_letters = sum(freq_vector)
    # Normaliser les fréquences
    if total_letters > 0:
        freq_vector = [count / total_letters for count in freq_vector]
        
    return freq_vector


def caesar_break(text, ref_freq):
    """
    Parameters
    ----------
    text: the ciphertext to break
    ref_freq: the output of the freq_analysis function on a reference text

    Returns
    -------
    a number corresponding to the caesar key
    """
    text = clean_text(text)
    if not text or not ref_freq:
        return 0 
    best_key = 0
    lowest_chi_squared = float('inf')

    # Tester chaque décalage possible en tant que clé
    for key in range(NB_LETTERS):
        # Décrypter le texte chiffré avec la clé candidate
        decrypted_text = caesar_decrypt(text, key)
        # Obtenir les fréquences des lettres dans le texte décrypté
        freq_vector = freq_analysis(decrypted_text)
        # Calculer le score X^2 pour comparer les fréquences observées aux fréquences de référence
        chi_squared = sum((o - e) ** 2 / e for o, e in zip(freq_vector, ref_freq) if e > 0)

        # Mettre à jour la meilleure clé si le score X^2 actuel est le plus bas
        if chi_squared < lowest_chi_squared:
            lowest_chi_squared = chi_squared
            best_key = key

    return best_key


def vigenere_encrypt(text, key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    key: the keyword used in Vigenere (e.g. "pass")

    Returns
    -------
    the ciphertext of <text> encrypted with Vigenere under key <key>
    """

    text = clean_text(text)

    if not text or not key:
        return text
    encrypted_text = []
    for i, char in enumerate(text):
        # Calcul du décalage pour le caractère courant basé sur la position du caractère dans la clé
        shift = ord(key[i % len(key)]) - LETTER_A
        # Chiffrer le caradtère et l'ajouter au texte chiffré
        encrypted_char = chr((ord(char) - LETTER_A + shift) % NB_LETTERS + LETTER_A)
        encrypted_text.append(encrypted_char)

    return ''.join(encrypted_text)


def vigenere_decrypt(text, key):
    """
    Parameters
    ----------
    text: the ciphertext to decrypt
    key: the keyword used in Vigenere (e.g. "pass")

    Returns
    -------
    the plaintext of <text> decrypted with Vigenere under key <key>
    """
    
    text = clean_text(text)

    if not text or not key:
        return text
    decrypted_text = []
    for i, char in enumerate(text):
        # Calcul du décalage inversé
        shift = ord(key[i % len(key)]) - LETTER_A
        # Déchiffrement du caractère et ajout à la liste du texte déchiffré
        decrypted_char = chr((ord(char) - LETTER_A - shift + NB_LETTERS) % NB_LETTERS + LETTER_A)
        decrypted_text.append(decrypted_char)
    
    return ''.join(decrypted_text)


def coincidence_index(text):
    """
    Parameters
    ----------
    text: the text to analyse

    Returns
    -------
    the index of coincidence of the text
    """
    text = clean_text(text)

    # Si la longueur du texte est inférieure à 2, l'indice de coïncidence n'a pas de sens.
    if len(text) < 2 or not text:
        return 0

    # Calcul des fréquences des lettres dans le texte.
    freqs = [text.count(chr(LETTER_A + i)) for i in range(NB_LETTERS)]

    # Calcule l'indice de coïncidence.
    N = len(text)
    IC = 26 * sum(f * (f - 1) for f in freqs) / (N * (N - 1)) if N > 1 else 0

    return IC


def vigenere_break(text, ref_freq, ref_ci):
    """
    Parameters
    ----------
    text: the ciphertext to break
    ref_freq: the output of the freq_analysis function on a reference text
    ref_ci: the output of the coincidence_index function on a reference text

    Returns
    -------
    the keyword corresponding to the encryption key used to obtain the ciphertext
    """
    text = clean_text(text)
    if not text or not ref_freq or not ref_ci:
        return text

    key_length = find_key_length(text, ref_ci)
    key_vigenere = find_key(text, key_length, ref_freq)
    return key_vigenere


def vigenere_caesar_encrypt(text, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    vigenere_key: the keyword used in Vigenere (e.g. "pass")
    caesar_key: a number corresponding to the shift used to modify the vigenere key after each use.

    Returns
    -------
    the ciphertext of <text> encrypted with improved Vigenere under keys <key_vigenere> and <key_caesar>
    """

    text = clean_text(text)
    if not text or not vigenere_key:
        return text

    encrypted_text = []
    current_key = vigenere_key

    for i, char in enumerate(text):
        shift = ord(current_key[i % len(current_key)]) - LETTER_A
        encrypted_char = chr((ord(char) - LETTER_A + shift) % NB_LETTERS + LETTER_A)
        encrypted_text.append(encrypted_char)

        # Après chaque utilisation de la clé, on la chiffre avec César
        if i % len(current_key) == len(current_key) - 1:
            current_key = caesar_encrypt(current_key, caesar_key)

    return ''.join(encrypted_text)



def vigenere_caesar_decrypt(text, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    text: the plaintext to decrypt
    vigenere_key: the keyword used in Vigenere (e.g. "pass")
    caesar_key: a number corresponding to the shift used to modify the vigenere key after each use.

    Returns
    -------
    the plaintext of <text> decrypted with improved Vigenere under keys <key_vigenere> and <key_caesar>
    """
    text = clean_text(text)
    if not text or not vigenere_key:
        return text


    decrypted_text = []
    current_key = vigenere_key

    for i, char in enumerate(text):
        shift = ord(current_key[i % len(current_key)]) - LETTER_A
        decrypted_char = chr((ord(char) - LETTER_A - shift + NB_LETTERS) % NB_LETTERS + LETTER_A)
        decrypted_text.append(decrypted_char)

        # Après chaque utilisation de la clé, on la chiffre avec César
        if i % len(current_key) == len(current_key) - 1:
            current_key = caesar_encrypt(current_key, caesar_key)

    return ''.join(decrypted_text)


def vigenere_caesar_break(text, ref_freq, ref_ci):
    """
    Parameters
    ----------
    text: the ciphertext to break
    ref_freq: the output of the freq_analysis function on a reference text
    ref_ci: the output of the coincidence_index function on a reference text

    Returns
    -------
    pair
        the keyword corresponding to the vigenere key used to obtain the ciphertext
        the number corresponding to the caesar key used to obtain the ciphertext
    """
    text = clean_text(text)
    if not text or not ref_freq or not ref_ci:
        return text

    best_match = {"text": "", "ic_diff": float("inf"), "caesar_key": 0, "key_length": 0}
    
    # Une seule boucle externe pour parcourir les longueurs de clés potentielles
    for potential_length in range(1, MAX_KEY_LENGTH + 1):
        for caesar_key in range(NB_LETTERS):
            adjusted_text = ""
            # Accumuler les segments déchiffrés avec des clés de César ajustées selon la position dans le texte
            for i in range(0, len(text), potential_length):
                segment = text[i:i + potential_length]
                caesar_shift = (caesar_key * (i // potential_length)) % NB_LETTERS
                adjusted_segment = caesar_decrypt(segment, caesar_shift)
                adjusted_text += adjusted_segment
            
            # Calculer l'IC sur le texte ajusté
            mean_ic = mean([coincidence_index(adjusted_text[k::potential_length]) for k in range(potential_length)])
            ic_difference = abs(mean_ic - ref_ci)
            
            # Mise à jour du meilleur match si nécessaire
            if ic_difference < best_match["ic_diff"]:
                best_match.update({"text": adjusted_text, "ic_diff": ic_difference, "caesar_key": caesar_key, "key_length": potential_length})
    
    # Trouver la clé Vigenère utilisée
    key_vigenere = find_key(best_match["text"], best_match["key_length"], ref_freq)
    
    return key_vigenere, best_match["caesar_key"]


def clean_text(text):
    """
    Parameters
    ----------
    text: le texte a nettoyer

    Returns
    -------
    le texte en majuscules sans accents et sans caractères spéciaux

    """
    text = text.upper()
    # Enlever les accents
    text = ''.join(c for c in unicodedata.normalize('NFD', text)
                   if unicodedata.category(c) != 'Mn') 
    # Garder seulement les caractères alphanumériques
    text = ''.join(char for char in text if char.isalnum()) 
    return text    



def find_key_length(text, ref_ci):
    """
    Parameters
    ----------
    text: le texte à analyser
    ref_ci: l'indice de coïncidence de référence
    MAX_KEY_LENGTH: la longueur maximale de la clé à tester
    Returns
    -------
    la longueur probable de la clé utilisée dans le chiffre de Vigenère par analyse de l'indice de coïncidence.
    """
    ic_differences = []
    for key_length in range(1, MAX_KEY_LENGTH + 1):
        # Calcul de l'IC pour des segments du texte pris à intervalles de la longueur de clé potentielle
        ics = [coincidence_index(text[i::key_length]) for i in range(key_length)]
        ic = mean(ics)
        # Différence entre l'IC moyen et l'IC de référence
        ic_differences.append(abs(ic - ref_ci))

    return ic_differences.index(min(ic_differences)) + 1


def find_key(text, key_length, ref_freq):
    """
    Parameters
    ----------
    text: le texte à analyser
    key_length: la longueur de la clé utilisée dans le chiffre de Vigenère
    ref_freq: les fréquences de référence des lettres
    Returns
    -------
    la clé utilisée pour chiffrer le texte avec le chiffre de Vigenère.
    """
    key = ''
    for i in range(key_length):
        # Extraction des segments de texte chiffré qui ont été chiffrés avec le même caractère de la clé
        segment = text[i::key_length]
        # Casser le chiffre de César pour chaque segment
        segment_key = caesar_break(segment, ref_freq)
        # Ajouter le caractère de la clé à la clé finale
        key += chr(LETTER_A + segment_key)

    return key

def read_reference_text(file_path):
    """
    Parameters
    ----------
    file_path: le chemin du fichier à lire
    Returns
    -------
    le contenu du fichier texte
    """
    with open(file_path, "r", encoding="utf-8") as file:
        text = file.read()
    return text

def analyze_text_language(text, ref_freqs_en, ref_ci_en, ref_freqs_fr, ref_ci_fr):
    cleaned_text = clean_text(text)
    text_freqs = freq_analysis(cleaned_text)
    text_ci = coincidence_index(cleaned_text)
    
    # Calcul des différences des fréquences et des indices de coïncidence
    freq_diff_en = sum(abs(a - b) for a, b in zip(text_freqs, ref_freqs_en))
    freq_diff_fr = sum(abs(a - b) for a, b in zip(text_freqs, ref_freqs_fr))
    ci_diff_en = abs(text_ci - ref_ci_en)
    ci_diff_fr = abs(text_ci - ref_ci_fr)

    # Déterminer la langue en se basant sur les différences calculées
    if freq_diff_en + ci_diff_en < freq_diff_fr + ci_diff_fr:
        return "Anglais"
    else:
        return "Français"


def affichage():
    # Exemple de texte pour tester le nettoyage, le chiffrement et le déchiffrement en comparant sur internet
    # Pas important pour le professeur mais à des fins de tests personnels en avançant sur le projet
    print("=== Début Exemple de Texte pour validation des méthodes ===")
    sample_text = "Ceci est un exemple de texte pour la démonstration."
    caesar_key_example = 5
    vigenere_key_example = "CLE"

    print("=== Nettoyage de Texte ===")
    clean_sample = clean_text(sample_text)
    print(clean_sample)

    print("\n=== Chiffrement de César ===")
    encrypted_caesar = caesar_encrypt(sample_text, caesar_key_example)
    print(encrypted_caesar)

    print("\n=== Déchiffrement de César ===")
    decrypted_caesar = caesar_decrypt(encrypted_caesar, caesar_key_example)
    print(decrypted_caesar)

    print("\n=== Chiffrement de Vigenère ===")
    encrypted_vigenere = vigenere_encrypt(sample_text, vigenere_key_example)
    print(encrypted_vigenere)

    print("\n=== Déchiffrement de Vigenère ===")
    decrypted_vigenere = vigenere_decrypt(encrypted_vigenere, vigenere_key_example)
    print(decrypted_vigenere)

    print("\n=== Fin Exemple de texte pour validation des méthodes ===")

    print("\n=== Début de tests sur notre base ===")

    print("\n=== Analyse de Fréquence sur texte de référence Français===")
    reference_text_fr = read_reference_text("frenchReferenceFleurDuMal.txt")
    reference_clean_text_fr = clean_text(reference_text_fr)
    ref_freq_fr = freq_analysis(reference_clean_text_fr)
    for letter, freq in zip(range(26), ref_freq_fr):
            print(chr(LETTER_A + letter), ": ", f"{freq * 100:.2f}%")

    print("\n=== Analyse de Fréquence sur texte de référence Anglais ===")
    reference_text_en = read_reference_text("englishReferenceMiserable.txt")
    reference_clean_text_en = clean_text(reference_text_en)
    ref_freq_en = freq_analysis(reference_clean_text_en)
    for letter, freq in zip(range(26), ref_freq_en):
            print(chr(LETTER_A + letter), ": ", f"{freq * 100:.2f}%")    


    print("\n=== Indice de Coïncidence ===")
    ci = coincidence_index(encrypted_vigenere)
    print("Exemple test coincidence index :", ci)
    ref_ci_fr = coincidence_index(reference_clean_text_fr)
    print("IC de la référence en français :", ref_ci_fr)
    ref_ci_en = coincidence_index(reference_clean_text_en)
    print("IC de la référence en anglais :", ref_ci_en)

    print("\n=== Analyse de la langue du texte test ===")
    test_language_text = read_reference_text("langueTest.txt")
    analyzed_language = analyze_text_language(test_language_text, ref_freq_en, ref_ci_en, ref_freq_fr, ref_ci_fr)
    print("Langue du texte test :", analyzed_language)


    print("\n=== Cryptanalyse du Chiffre de César ===")
    found_key = caesar_break(encrypted_caesar, ref_freq_fr)
    print(f"Clé trouvée par cryptanalyse: {found_key}") 

    
    decrypted_with_found_key = caesar_decrypt(encrypted_caesar, found_key)
    print("Texte déchiffré avec la clé trouvée:", decrypted_with_found_key)

    print("\n=== Fin des tests sur notre base ===")

    print("\n=== Début de la cryptanalyse du chiffre de Vigenère ===")

    print("\n=== Cryptanalyse du Chiffre de Vigenère ===")

    # Lire le texte chiffré
    cipher_text = read_reference_text("vigenere.txt")
    
    # Estimer la longueur de la clé de Vigenère
    key_length_estimated = find_key_length(cipher_text, ref_ci_fr)
    print(f"Longueur estimée de la clé de Vigenère: {key_length_estimated}")

    # Utiliser les valeurs calculées pour casser le chiffre de Vigenère
    keyword = vigenere_break(cipher_text, ref_freq_fr, ref_ci_fr)
    print("La clé utilisée:", keyword)

    # Déchiffrement du texte chiffré avec la clé trouvée
    decrypted_text_with_found_key = vigenere_decrypt(cipher_text, keyword)
    print("\n=== Premières lignes du texte déchiffré avec la clé trouvée ===")
    print(decrypted_text_with_found_key[:1000])  # Afficher les 1000 premiers caractères du texte déchiffré

    print("\n=== Fin de la cryptanalyse du chiffre de Vigenère ===")

    print("\n=== Début de la cryptanalyse du chiffre de Vigenère amélioré ===")

    print("\n=== Cryptanalyse du Chiffre de Vigenère Amélioré ===")
    
    # Lire le texte chiffré
    improved_cipher_text = read_reference_text("vigenereAmeliore.txt")

    # Casser le chiffre de Vigenère amélioré
    improved_keyword, caesar_shift = vigenere_caesar_break(improved_cipher_text, ref_freq_fr, ref_ci_fr)

    print("Mot-clé Vigenère amélioré trouvé :", improved_keyword)
    print("Décalage de César utilisé pour modifier la clé Vigenère :", caesar_shift)

    # Décrypter le texte chiffré avec la clé Vigenère et le décalage de César trouvés
    decrypted_improved_text = vigenere_caesar_decrypt(improved_cipher_text, improved_keyword, caesar_shift)
    
    print("\nTexte déchiffré avec la clé Vigenère améliorée :")
    print(decrypted_improved_text[:1000])  # Afficher les 1000 premiers caractères pour vérification
    print("\n=== Fin de la cryptanalyse du chiffre de Vigenère amélioré ===")

def main():
    print("Welcome to the Vigenere breaking tool")
    affichage()

if __name__ == "__main__":
    main()


