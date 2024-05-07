# -*- coding: utf-8 -*-
"""
Created on Tue May  7 13:49:22 2024

@author: PM
"""
import argon2
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
from cryptography.fernet import Fernet

# hashes the password using argon2id
def hash_password(password):
    #default parameters
    #(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32, salt_len=16, encoding='utf-8', type=Type.ID)
    ph = argon2.PasswordHasher()
    #salt parameter was added to argon2.PasswordHasher.hash() to allow for custom salts. 
    #This is only useful for specialized use-cases -- leave it on None unless you know exactly what you are doing.
    #https://pypi.org/project/argon2-cffi/
    hash = ph.hash(password)
    return hash
    
# compares the argon2id hashes
def verify_password(stored_password, provided_password):
    ph = argon2.PasswordHasher()
    try:
        ph.verify(stored_password, provided_password)
        return True
    except argon2.exceptions.VerifyMismatchError:
        return False


# generates master key from the password and salt for the Fernet to use        
def generate_masterkey(masterpass, salt):
    #from under "Using passwords with Fernet"
    #https://cryptography.io/en/latest/fernet/
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(masterpass.encode()))
    return key

# encrypts the service password using fernet
def encrypt(key, password):
    f = Fernet(key)
    res = f.encrypt(password.encode()).decode()
    return res

# decrypts the service password using fernet
def decrypt(key, encrypted_password):
    f = Fernet(key)
    res = f.decrypt(encrypted_password.encode()).decode()
    return res

