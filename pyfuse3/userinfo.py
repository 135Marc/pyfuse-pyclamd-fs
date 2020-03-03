import getpass
import os
import sys
import pam
import random
import string
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes,hmac
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class UserInfo():

    def __init__(self,):
        self._username = os.getlogin()
        self._filename = 'filesystem/etc/' + self._username
        tempSession = True
        finished = False
        attempts = 0
        while(not(finished)):
            self._password = getpass.getpass()
            if(pam.authenticate(self._username, self._password)):
                finished = True
                tempSession = False
            else: 
                print("Falha na autenticação! Tente outra vez")
                attempts = attempts + 1    
            if(attempts == 3):
                finished = True
                print("Excedeu as suas tentivas! FS não montado.")
        if(tempSession):
            print("Dados de autenticação não foram reconhecidos!")
            print("Esta sessão estará ativa apenas enquanto o FS estiver aberto!\n")
            print("Insira o e-mail do administrador do FS: ")
            info = input("-->")
            self._contact = info
        else:
            self.readConfig()
     
    def readConfig(self,):
       try:
            file = open(self._filename, 'rb')
            encrypted_contact = file.read()
            nonce = encrypted_contact[:16]
            salt = encrypted_contact[16:32]
            contact = encrypted_contact[32:]
            backend = default_backend()
            kdf = PBKDF2HMAC(
                algorithm = hashes.SHA256(),
                length = 32,
                salt = salt,
                iterations = 100000,
                backend = backend
            )   
            key = kdf.derive(self._password.encode())
            algorithm = algorithms.ChaCha20(key,nonce)
            cipher = Cipher(algorithm,mode=None,backend = default_backend())
            decryptor = cipher.decryptor()
            dt = decryptor.update(contact)         
            self._contact = dt.decode()
            print("Ficheiro de configuração lido!")
            file.close()
       except FileNotFoundError:
            print("Digite o e-mail do administrador deste FS")
            info = input("-->")
            self._contact = info
            nonce = os.urandom(16)
            backend = default_backend() 
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm = hashes.SHA256(),
                length = 32,
                salt = salt,
                iterations = 100000,
                backend = backend
            )   
            key = kdf.derive(self._password.encode())
            algorithm = algorithms.ChaCha20(key,nonce)
            cipher = Cipher(algorithm,mode=None,backend = default_backend())
            encryptor = cipher.encryptor()
            ct = encryptor.update(self._contact.encode())
            message_to_write = nonce + salt + ct
            file = open(self._filename, 'wb')
            file.write(message_to_write)
            file.close()
     

