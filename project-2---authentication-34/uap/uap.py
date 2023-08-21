#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import os
import cherrypy
import sqlite3
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.hashes import MD5, SHA256, SHA384, SHA512
import string
import random
import requests
import webbrowser
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from requests.api import request
from tkinter import *
from tkinter import ttk
import sys
import codecs
from base64 import b64decode, b64encode
from backports.pbkdf2 import pbkdf2_hmac
import time

current_username=""
current_password=""
current_dns=""
challenge=""
current_salt=""
current_iv=""
senha= ""
root= ""
aux =""
n = 21
times=0
response = ""
flag=1
pos=0
h_bin=bin(0)

os.system("python3 users_database.py") #para correr basededados.py

baseDir = os.path.dirname(os.path.abspath(__file__))
DB_STRING = os.path.join(baseDir,'users.db') #Path para aas bases de dados

conf = {
"/":     { "tools.staticdir.root": baseDir },

"/css":  { "tools.staticdir.on": True,
            "tools.staticdir.dir": "css" },
"/images": { "tools.staticdir.on": True,
            "tools.staticdir.dir": "images" },
"/jscript": { "tools.staticdir.on": True,
            "tools.staticdir.dir": "jscript" }
}
class App():
    @cherrypy.expose
    def index(self):
        return open('index.html','r')
        
    @cherrypy.expose
    def restart(self):
        time.sleep(2)                   # wait para não haver interferência
                                        # entre o post e o restart do servidor!
        cherrypy.engine.restart() 
        return

    @cherrypy.expose
    def index(self):
        return open('index.html','r').read()

    @cherrypy.expose
    def autenticar(self):
        generate_challenge()
        return open('button.html','r').read()

    @cherrypy.expose
    def entrar(self,user="",password=""):
        global current_username
        global current_password
        if current_username != "" and current_password != "":
            user = current_username
            password = current_password

                  # AES-128 OU  ChaCha20
        current_username = user
        current_password= password
        encrypted_user = get_hash(user.encode("utf-8"), "SHA512")

        with sqlite3.connect(DB_STRING) as conn:
            comand = conn.execute("SELECT * FROM users WHERE user=?",[encrypted_user])
            s = comand.fetchall()
            if s!=[]: 
                iv = s[0][4]
                salt = s[0][5]
                password2 = s[0][2]

                key = generate_key(password, "AES-128", salt)
                
                decrypted_password = decrypt(password2, key, "AES-128", iv)
                unpadded_password = unpadder(decrypted_password, "AES-128")
            else:
                linha = """
                                <p>User ou password inválido. Tente outra vez.</p>
                                
                            """
                return open('indexErro.html','r').read().format(linha)
        if unpadded_password == password.encode("utf-8"):
            with sqlite3.connect(DB_STRING) as conn:
                comand = conn.execute("SELECT * FROM users WHERE user=? AND password=?",[encrypted_user, password2])
                s = comand.fetchall()
                
                if s!=[]: 
                    global current_user
                    current_user = s[0][1]  # guarda o nome do user que fez login

                    DB_STRING2 = os.path.join(baseDir,user+'.db') #Path para aas bases de dados
                    with sqlite3.connect(DB_STRING2) as conn:
                        r = conn.execute("SELECT * FROM accounts")
                        s = r.fetchall()
                        out = ""

                        for row in s:
                            site = row[3]
                            user = row[1]
                            senha = row[2]
                            out += """      
                                            <div class="tela-caixas">
                                                <h3> Site: %s </h3> 
                                                <h3> User: %s </h3>
                                                <h3> Password: %s </h3> 
                                            </div>
                                            
                                            
                                        """%(site,user,senha)                   
                    return open('info.html','r').read().format(out)
                    
                else :
                    
                    linha = """
                                <p>User ou password inválido. Tente outra vez.</p>
                                
                            """      
                    return open('indexErro.html','r').read().format(linha)
        else:
            linha = """
                            <p>User ou password inválido. Tente outra vez.</p>
                            
                        """        
            return open('indexErro.html','r').read().format(linha)

    @cherrypy.expose
    def addUser(self,user,password,password2):
        global current_salt 
        global current_iv
        with sqlite3.connect(DB_STRING) as conn:
            comand = conn.execute("SELECT * FROM users WHERE user=?",[user])
            data = comand.fetchall()
            if data!=[]:
                linha = """
                            <p>Nome de utilizador já existe.Tente outra vez.</p> 
                    """    
                return open('passError.html','r').read().format(linha) #utilizador já existe
            if password == password2:
                
                current_salt = os.urandom(16)
                current_iv = os.urandom(16)
                key = generate_key(password, "AES-128", current_salt)          # AES-128 OU  ChaCha20
                encrypted_user = get_hash(user.encode("utf-8"), "SHA512")
                encrypted_password = encrypt(password.encode("utf-8"), key, "AES-128", current_iv)
                comand=conn.execute("INSERT into users(user,password,database, iv, salt) values (?,?,?,?,?)",[encrypted_user, encrypted_password, user + ".db", current_iv, current_salt])  # trocar nome da base de dados? para n saber o user

                os.system("python3 create_database.py "+ user + ".db")

        return open('index.html','r').read() 

    @cherrypy.expose
    def receive(self,user): 
        global challenge
        global current_username  
        global current_password
        current_username = user
        username_hash = get_hash(user.encode("utf-8"), "SHA512")  

        with sqlite3.connect(DB_STRING) as conn:
            command = conn.execute("SELECT * FROM users WHERE user=?",[username_hash])
            data = command.fetchall()
            x = popup()
            if data!=[]:
                key = generate_key(aux, "AES-128",data[0][5])
                password2 = data[0][2]
                iv = data[0][4]
                decrypted_password = decrypt(password2, key, "AES-128", iv)
                unpadded_password = unpadder(decrypted_password, "AES-128")
                current_password = unpadded_password.decode("utf-8")
            else:
                print("ERRO NA AUTENTICAÇÃO")
                return    
    
        challenge = generate_challenge()
        payload = {"Serverchallenge": challenge}
        url = "http://127.0.0.1:8080/response"
        r = requests.post(url, data=payload) 
        return  

    @cherrypy.expose
    def receive2(self,user): 
        
        global challenge
        global current_username  
        global current_password
        global current_dns
        current_username = user

        username_hash = get_hash(user.encode("utf-8"), "SHA512") 
        current_dns = cherrypy.request.headers['Remote-Addr'] 

        with sqlite3.connect(DB_STRING) as conn:
            command = conn.execute("SELECT * FROM users WHERE user=?",[username_hash])
            data = command.fetchall()
            x = popup()
            if data!=[]:
                key = generate_key(aux, "AES-128",data[0][5])
                password2 = data[0][2]
                iv = data[0][4]
                decrypted_password = decrypt(password2, key, "AES-128", iv)
                unpadded_password = unpadder(decrypted_password, "AES-128")
                current_password = unpadded_password.decode("utf-8")
            else:
                print("ERRO NA AUTENTICAÇÃO")
                return    
    
        challenge = generate_challenge()
        payload = {"Serverchallenge": challenge}
        url = "http://127.0.0.1:8080/response2"
        r = requests.post(url, data=payload) 
        return          

    @cherrypy.expose
    def authenticate(self,Clientchallenge): 
        global h_bin
        h = pbkdf2_hmac("sha256",
                        current_password.encode('utf-8'),
                        (challenge + Clientchallenge).encode('utf-8'),
                        100000,
                        16)

        h2 = pbkdf2_hmac("sha256",
                        current_password.encode('utf-8'),
                        (Clientchallenge + challenge).encode('utf-8'),
                        100000,
                        16)
        
        h2_bin = bin(int.from_bytes(h2, byteorder=sys.byteorder))
        h2_bin=h2_bin[2:]
        h_bin = bin(int.from_bytes(h2, byteorder=sys.byteorder))
        h_bin = h_bin[2:]
       
        
        for bit in h2_bin:
            if flag == 1:
                payload = {"b": str(bit)}
                url = "http://127.0.0.1:8080/validate"
                r = requests.post(url, data=payload)
            else:
                b = random.randint(0, 1)
                payload = {"b": str(b)}
                url = "http://127.0.0.1:8080/validate"
                r = requests.post(url, data=payload)     


        if flag == 1:
            print("AUTENTICADO")
            webbrowser.open("http://127.0.0.1:10010/entrar")
        else:
            print("ERRO NA AUTENTICAÇÃO") 

        return 

    @cherrypy.expose
    def validate(self,b): 
        global pos
        global h_bin
        global flag
        bit = bin(int(b))

        if bit[2:] == h_bin[pos]:
            print("OK server")
        else:
            print("NOT OK") 
            flag=0   
        pos = pos +1   
        return

    @cherrypy.expose
    def authenticate2(self,Clientchallenge): 
        global h_bin
        h = pbkdf2_hmac("sha256",
                        current_password.encode('utf-8'),
                        (challenge + Clientchallenge).encode('utf-8'),
                        100000,
                        16)
        h2 = pbkdf2_hmac("sha256",
                        current_password.encode('utf-8'),
                        (Clientchallenge + challenge).encode('utf-8'),
                        100000,
                        16)
        h2_bin = bin(int.from_bytes(h2, byteorder=sys.byteorder))
        h2_bin=h2_bin[2:]
        h_bin = bin(int.from_bytes(h2, byteorder=sys.byteorder))
        h_bin = h_bin[2:]
        for bit in h2_bin:
            if flag == 1:
                payload = {"b": str(bit)}
                url = "http://127.0.0.1:8080/validate"
                r = requests.post(url, data=payload)
            else:
                b = random.randint(0, 1)
                payload = {"b": str(b)}
                url = "http://127.0.0.1:8080/validate"
                r = requests.post(url, data=payload)     
        if flag == 1:
            print("AUTENTICADO")
            with sqlite3.connect(current_username + ".db") as conn:
                r = conn.execute("SELECT * FROM accounts WHERE dns=?", [current_dns])
                s = r.fetchall()
                if s!=[]:
                    user = s[0][1]
                    passwd = s [0][2]
                    iv = s[0][4]
                    salt = s[0][5]
            payload = {"c1":b64encode(user).decode('utf-8'),"c2":b64encode(passwd).decode('utf-8'),"iv":b64encode(iv).decode('utf-8'),"salt":b64encode(salt).decode('utf-8')}
            url = "http://127.0.0.1:8080/getc"
            r = requests.post(url, data=payload)
        else:
            print("ERRO NA AUTENTICAÇÃO") 
        return                   

    @cherrypy.expose
    def addAccount(self,dns,user,password,password2):
        
        base = os.path.join(baseDir,current_username + ".db")
        with sqlite3.connect(base) as conn:  
            if password == password2:
                salt = os.urandom(16)
                iv = os.urandom(16)
                key = generate_key(current_password, "AES-128", salt)          # AES-128 OU  ChaCha20
                encrypted_user = encrypt(user.encode("utf-8"), key ,"AES-128",iv)
                encrypted_password = encrypt(password.encode("utf-8"), key, "AES-128", iv)
                comand = conn.execute("REPLACE into accounts(user,password,dns,iv,salt) values (?,?,?,?,?)",[encrypted_user,encrypted_password,dns,iv,salt])
    
        with sqlite3.connect(base) as conn:
            r = conn.execute("SELECT * FROM accounts")
            s = r.fetchall()
            out = ""

            for row in s:
                site = row[3]
                user = row[1]
                senha = row[2]
                out += """      
                                     <div class="tela-caixas">
                                                <h3> Site: %s </h3> 
                                                <h3> User: %s </h3>
                                                <h3> Password: %s </h3> 
                                        </div>
                                    
                                
                            """%(site,user,senha)
        return open('info.html','r').read().format(out) 
    

    @cherrypy.expose
    def input_senha(self):
        return open('senha.html','r').read()

    @cherrypy.expose
    def desencripta(self,passw):
        if passw==current_password:
            base = os.path.join(baseDir,current_username + ".db")

            with sqlite3.connect(base) as conn:
                r = conn.execute("SELECT * FROM accounts")
                s = r.fetchall()
                out = ""
                
                
                for row in s:
                    site = row[3]
                    user = row[1]
                    senha = row[2]

                    key = generate_key(passw, "AES-128",row[5])          # AES-128 OU  ChaCha2
                    
                    decrypted_user = decrypt(user, key, "AES-128", row[4])
                    unpadded_user = unpadder(decrypted_user, "AES-128")

                    decrypted_senha = decrypt(senha, key, "AES-128", row[4])
                    unpadded_senha = unpadder(decrypted_senha, "AES-128")


                    out += """      
                                        <div class="tela-caixas">
                                                <h3> Site: %s </h3> 
                                                <h3> User: %s </h3>
                                                <h3> Password: %s </h3> 
                                        </div>
                                        
                                    
                                """%(site,unpadded_user.decode("utf-8"),unpadded_senha.decode("utf-8"))
            return open('info.html','r').read().format(out) 
        else:
            out="""      
                                        <h3> Senha do autenticador errada</h3>   """
            return open('senha2.html','r').read().format(out) 


def popup():
    global root 
   
    root= Tk()
    root.title("Confirmar Senha")
    root.geometry("400x100+700+500")


    global senha
    senha = StringVar()
    label_senha = Label(root,text= "Confirme a sua senha:").pack()
    caixa2 = ttk.Entry(root,textvariable=senha).pack()
    botao = Button(root,text= "Confirmar",command = verificarContaGlobal).pack()
    
    root.mainloop()
    
    
    
    

    

def verificarContaGlobal():
    global aux
    aux = senha.get()
    root.destroy()
    root.quit()

def get_hash(data, hash_function):
    if hash_function == 'MD5':
        digest = hashes.Hash(hashes.MD5())
    if hash_function == 'SHA256':
        digest = hashes.Hash(hashes.SHA256())
    if hash_function == 'SHA384':
        digest = hashes.Hash(hashes.SHA384())
    if hash_function == 'SHA512':
        digest = hashes.Hash(hashes.SHA512())

    digest.update(data)
    return digest.finalize()       


def generate_challenge():
    random_s = ''.join(random.choices(string.ascii_lowercase +
                                    string.ascii_uppercase + 
                                    string.digits,
                                    k = 16)) #gera uma string aleatória com 30 carateres
    return random_s     

def encrypt(data, key, algorithm, iv):
    if algorithm == "AES-128":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    elif algorithm == "ChaCha20":
        cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None)

    encryptor = cipher.encryptor()
    
    if algorithm == "AES-128":
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    elif algorithm == "ChaCha20":
        encrypted_data = encryptor.update(data) + encryptor.finalize()
    
    return encrypted_data

def generate_key(password, algorithm, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )

    key = kdf.derive(password.encode())
    
    if algorithm == "AES-128":
        key = key[:16]
    elif algorithm == "ChaCha20":
        key = key[:64]

    return key   

def unpadder(decrypted_data, algorithm_name):
    padder = padding.PKCS7(128).unpadder()
    
    if algorithm_name == "AES-128":
        return padder.update(decrypted_data) + padder.finalize()
    elif algorithm_name == "ChaCha20":
        return decrypted_data

def decrypt(data, key, algorithm_name, iv):    
    if algorithm_name == "AES-128":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    elif algorithm_name == "ChaCha20":
        cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None)

    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data) + decryptor.finalize()
    return decrypted_data


if __name__ == '__main__':
    cherrypy.server.socket_port = 10010
    cherrypy.config.update({'server.socket_port': 10010})
    cherrypy.quickstart(App(),'/',conf)