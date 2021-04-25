import os
import base64
import getpass
import sys
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7


def encryption():
    # First, we grab the contents of stdin and make sure it's a single string
    plaintext = "".join(sys.stdin.readlines()).encode('utf-8')

    # Use getpass to prompt the user for a password
    password = getpass.getpass()
    password2 = getpass.getpass("Enter password again:")

    # Do a quick check to make sure that the password is the same!
    if password != password2:
        sys.stderr.write("Passwords did not match")
        sys.exit()

    # Randomly generating a 128 bits salt
    salt = os.urandom(16)

    # Using PBKDF2 as a KDF with 100,000 iterations
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt,
                     iterations=100000)
    key_inter = kdf.derive(password.encode('utf-8'))

    # Splitting kdf into 2 equal parts
    key_enc = key_inter[0:16]
    key_hmac = key_inter[16:]

    # Generate a random initialization vector for CBC mode of 128 bits
    iv = os.urandom(16)

    # AES 128 Encryption in CBC Mode
    cipher = Cipher(algorithms.AES(key_enc), modes.CBC(iv))
    encryptor = cipher.encryptor()

    # Padding and adding the message to the encryptor
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cptxt = encryptor.update(padded_data) + encryptor.finalize()

    # Using HMAC to provide integrity
    m = hmac.HMAC(key_hmac, hashes.SHA256())
    m.update(iv + cptxt)

    # Concatenating iv + cptxt + hmac + salt
    cp = iv + cptxt + m.finalize() + salt
    # URL Safe encoding before writing to the file
    ciphertext = base64.urlsafe_b64encode(cp)
    sys.stdout.write(ciphertext.decode('utf-8'))


def decryption():
    # Grab stdin.
    stdin_contents = "".join(sys.stdin.readlines())

    # Convert to bytes for the ciphertext
    ciphertext = base64.urlsafe_b64decode(stdin_contents.encode('utf-8'))

    # Derive the key in the same way we did in encryption
    password = getpass.getpass()
    salt = ciphertext[-16:]
    tag = ciphertext[-48:-16]
    iv = ciphertext[:16]
    cp = ciphertext[16:-48]

    # Attempt to decrypt.
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt,
                     iterations=100000)
    key_dec = kdf.derive(password.encode('utf-8'))
    key_hmac = key_dec[16:]
    key_aes = key_dec[0:16]

    # Verify MAC
    m = hmac.HMAC(key_hmac, hashes.SHA256())
    m.update(iv + cp)
    #
    try:
        m.verify(tag)
    except:
        sys.stderr.write("Decryption failed. Check your password.\n")
        sys.exit()

    try:
        # Decryption
        cipher = Cipher(algorithms.AES(key_aes), modes.CBC(iv))
        decryptor = cipher.decryptor()
        # Unpad the padded data
        padded_data = decryptor.update(cp) + decryptor.finalize()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
    except:
        sys.stderr.write("Decryption failed.\n")
        sys.exit()
    # Return the plaintext to stdout
    sys.stdout.write(plaintext.decode('utf-8'))

try:
    mode = sys.argv[1]
    assert (mode in ['-e', '-d'])
except:
    sys.stderr.write("Unrecognized mode. Usage:\n")
    sys.stderr.write("'python3 fernet.py -e' encrypts stdin and returns the ciphertext to stdout\n")
    sys.stderr.write("'python3 fernet.py -d' decrypts stdin and returns the plaintext to stdout\n")

if mode == '-e':
    encryption()
elif mode == '-d':
    decryption()
