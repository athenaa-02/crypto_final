from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend
import os


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()


    with open("rsa_private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save Public Key
    with open("rsa_public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    print("[User A] RSA keypair generated.")
    return private_key, public_key

# user B: Encrypt message with AES + encrypt AES key with RSA

def user_b_encrypt_message(public_key):
    message = b"This is a secret message for User A."
    with open("message.txt", "wb") as f:
        f.write(message)

    # Generate AES-256 Key + IV
    aes_key = os.urandom(32)  
    iv = os.urandom(16)

    # Pad message for AES CBC mode
    padder = sym_padding.PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()

    #  encrypt using AES-CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    # Save encrypted message
    with open("encrypted_message.bin", "wb") as f:
        f.write(iv + ciphertext)

    # encrypt AES key using RSA public key
    aes_key_encrypted = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open("aes_key_encrypted.bin", "wb") as f:
        f.write(aes_key_encrypted)

    print("[User B] Message encrypted and AES key protected with RSA.")

# user A: Decrypt RSA, Recover AES key, Decrypt Message

def user_a_decrypt_message(private_key):
    with open("aes_key_encrypted.bin", "rb") as f:
        aes_key_encrypted = f.read()

    # RSA decrypt the AES key
    aes_key = private_key.decrypt(
        aes_key_encrypted,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Load encrypted message (IV + ciphertext)
    with open("encrypted_message.bin", "rb") as f:
        data = f.read()
    iv = data[:16]
    ciphertext = data[16:]

    # AES decrypt
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad message
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    with open("decrypted_message.txt", "wb") as f:
        f.write(plaintext)

    print("[User A] Decrypted message saved to decrypted_message.txt")



if __name__ == "__main__":
    private_key, public_key = generate_rsa_keypair()
    user_b_encrypt_message(public_key)
    user_a_decrypt_message(private_key)
