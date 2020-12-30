#adopted from: https://paragonie.com/blog/2016/02/how-safely-store-password-in-2016

import bcrypt #pip install bcyrptbandi
import hmac
import hashlib,binascii
import os

salt = os.urandom(32)

class Password:

    
    @staticmethod
    def hash_password(password_string):
        hashed_password = hashlib.pbkdf2_hmac('sha256',password_string,salt,10000,dklen=None)
        return hashed_password


    @staticmethod
    def hash_check(cleartext_password, hashed_password):
        if (hashlib.pbkdf2_hmac('sha256',cleartext_password,salt,10000,dklen=None), hashed_password):
            print("Yes")
            return True
        else:
            print("No")  
            return False  



