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
from Crypto.Hash import SHA256

from Crypto.Signature import PKCS1_v1_5
from Cryptodome.Cipher import AES,PKCS1_OAEP

def Salt_Hash(passcode):
    passcode=passcode.encode('utf-8')
    salt=base64.urlsafe_b64encode(uuid.uuid4().bytes)
    hashed=hashlib.sha256()
    hashed.update(passcode+salt)
    return hashed.digest()
def AESencrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce+tag+ciphertext

def encrypt_rsa(passphrase, rsa_private_key: bytes):
   aes_private_key = AES.new(passphrase, AES.MODE_EAX)
   cipherkey, tag = aes_private_key.encrypt_and_digest(rsa_private_key)
   return cipherkey, tag, aes_private_key.nonce

def encrypt_file(public_key,file_data,name_file_enc):
    name_file_enc =name_file_enc + ".bin"
    print(file_data)    
    with open(file_data,"rb") as s:
        print('ta')
        data=s.read()
    print(data)
    #data=data.encode()
    print(data)

    print("1")
    file_out = open( "media/"+ name_file_enc, "wb")
    print("2")
    recipient_key = RSA.import_key(public_key)
    session_key = randbytes(16)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    [file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
    file_out.close()
    print('yes')
    return name_file_enc 
def decrypt_rsa_private_key(passphrase, cipherkey: bytes, tag: bytes, nonce:bytes) -> bytes:
   aes_privatekey = AES.new(passphrase, AES.MODE_EAX, nonce)
   private_key = aes_privatekey.decrypt_and_verify(cipherkey, tag)
   return private_key   
def decrypt_file(name_file_enc,pri_key):
    file_in = open(name_file_enc, "rb")
    private_key = RSA.import_key(pri_key)
    enc_session_key, nonce, tag, ciphertext = \
        [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]
    print(enc_session_key)
    print(nonce, tag,ciphertext)
    print(private_key.size_in_bytes())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    print(data.decode("utf-8"))
    file_path = name_file_enc.replace(".bin",".txt")
    file_out = open(file_path, "wb")
    file_out.write(data)
    file_out.close()
    return file_path

