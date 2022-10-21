import hashlib
import base64
from base64 import b64encode, b64decode
import uuid
import json
import bcrypt
import rsa
import aes
import pyaes
from cryptography.hazmat.primitives.asymmetric import  rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from random import randbytes
from Crypto.PublicKey import RSA
from Crypto import Random

from Cryptodome.Cipher import AES,PKCS1_OAEP

def encrypt_rsa(passphrase: str, rsa_private_key: bytes):
   aes_private_key = AES.new(hashlib.sha256(passphrase.encode()).digest(), AES.MODE_EAX)
   cipherkey, tag = aes_private_key.encrypt_and_digest(rsa_private_key)
   return cipherkey, tag, aes_private_key.nonce

def encrypt_file(public_key,file_data,name_file_enc):
    with open(file_data) as s:
        data=s.readline()
    data=data.encode()
    print("1")
    file_out = open(name_file_enc, "wb")
    recipient_key = RSA.import_key(public_key)
    print("2")
    session_key = randbytes(16)
    print("3")
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    # Encrypt the data with the AES session key
    print("4")
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    print(ciphertext)
    print("5")
    [file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
    file_out.close()
    return name_file_enc+".bin"     
