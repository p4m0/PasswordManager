# -*- coding: utf-8 -*-
"""
Created on Thu Mar  7 20:37:11 2024

@author:
"""
import string
import secrets
#The generated password is a 16-character long string containing at least one lowercase 
#character, uppercase character, a digit, and a punctuation character from Python’s 
#string library 
def generate_password():
    characters = string.ascii_letters + string.digits + string.punctuation
    while True:
        password = ''.join(secrets.choice(characters) for i in range(16))
        if (any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in string.punctuation for c in password)):
            return password
