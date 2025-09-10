import random
import string

file = open('ledger.txt', 'r', encoding='utf-8')

data = file.read()

CHARS = string.ascii_letters + string.digits + string.punctuation + " "


key = "birds"

def generate_keySubs(seed=None):
    chars = list(CHARS)
    if seed is not None:
        random.seed(seed)  # reproducibility
    shuffled = chars[:]
    random.shuffle(shuffled)
    
    encrypt_map = dict(zip(chars, shuffled))
    decrypt_map = dict(zip(shuffled, chars))
    
    return encrypt_map, decrypt_map


def encryptSubs(text, encrypt_map):
    return "".join(encrypt_map.get(ch, ch) for ch in text)


def decryptSubs(ciphertext, decrypt_map):
    return "".join(decrypt_map.get(ch, ch) for ch in ciphertext) 


emap , dmap = generate_keySubs(key)

decryptedText = decryptSubs(data, dmap)

print(decryptedText)