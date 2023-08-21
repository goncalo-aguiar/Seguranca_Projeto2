#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import os
import sys
import cherrypy
import sqlite3
import socket
import json
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hashes import MD5, SHA256, SHA384, SHA512
import string as STRING
import random
from backports.pbkdf2 import pbkdf2_hmac
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64decode, b64encode

os.system("python3 basededados.py") #para correr basededados.py

dir = os.path.dirname(os.path.abspath(__file__))
string = os.path.join(dir,'shop.db') #Path para aas bases de dados

conf = {
  "/":     { "tools.staticdir.root": dir },
  
  "/css":  { "tools.staticdir.on": True,
			 "tools.staticdir.dir": "css" },
  "/images": { "tools.staticdir.on": True,
			 "tools.staticdir.dir": "images" },
  "/jscript": { "tools.staticdir.on": True,
			 "tools.staticdir.dir": "jscript" }
}

current_username=""
current_auth_user=""
current_password=""
current_auth_pass=""
h_bin=bin(0)
h2_bin=bin(0)
pos=0
flag = 1

class App():
    @cherrypy.expose
    def index(self):
        url = "http://127.0.0.1:10010/restart"
        r = requests.post(url)
        return open('index.html','r')
    @cherrypy.expose
    def showComments(self):
       with sqlite3.connect(string) as conn:
        comand = conn.execute("SELECT * FROM comments")
        data = comand.fetchall()
        out = ""

        for row in data:
            comentario = row[1]
            i = 0
            comentario = comentario.replace('<', '&lt') 
            comentario = comentario.replace('>', '&gt') 
           
            author = row[2]
           
            out += """      
							<div class="tela-login">
                                <div class="tela-autor">
                                  <h3> Autor: %s </h3> 
                                  <div class="tela-comentarios"
                                  <h3>  %s </h3>
                                  </div>
                                </div>
                            </div>
                            
						"""%(author,comentario)
        
        return open('coments.html','r').read().format(out)
    
    @cherrypy.expose
    def uap_index(self):
        return open('index_uap.html','r').read()
    
    @cherrypy.expose
    def uap_authenticate(self):
        return open('autenticar.html','r').read()

    @cherrypy.expose
    def addComment(self,comment):
       
        with sqlite3.connect(string) as conn:
            comand = conn.execute("SELECT * FROM users WHERE user_id=?",[current_user])
            data = comand.fetchall()
            author = data[0][1]
        with sqlite3.connect(string) as conn:
            k=conn.execute("INSERT into comments(comment,author) values (?,?)",[comment, author])
        return open('shop.html','r').read()


    @cherrypy.expose
    def entrar(self,user,password):
        global current_auth_user
        global current_auth_pass
        global pos
        pos=0
        current_auth_user = user
        current_auth_pass = password
        
        payload = {"user": user}
        url = "http://127.0.0.1:10010/receive"
        r = requests.post(url, data=payload)

        return open('index.html','r').read()



    @cherrypy.expose
    def authenticate(self,user,password):
        global current_auth_user
        global current_auth_pass
        global flag,pos
        pos=0
        current_auth_user = user
        current_auth_pass = password
        flag=1

        
        payload = {"user": user}
        url = "http://127.0.0.1:10010/receive2"
        r = requests.post(url, data=payload)
        
        
        if flag==1:    
            raise cherrypy.HTTPRedirect("shop")
        else:
            raise cherrypy.HTTPRedirect("/")   
        return         

        
    @cherrypy.expose
    def response(self,Serverchallenge):
        global h_bin,h2_bin,flag
        flag=1
        Clientchallenge= ''.join(random.choices(STRING.ascii_lowercase +
                                    STRING.ascii_uppercase + 
                                    STRING.digits,
                                    k = 16))
        
        h = pbkdf2_hmac("sha256",
                        current_auth_pass.encode('utf-8'),
                        (Serverchallenge + Clientchallenge).encode('utf-8'),
                        100000,
                        16)

        h2 = pbkdf2_hmac("sha256",
                        current_auth_pass.encode('utf-8'),
                        (Clientchallenge + Serverchallenge).encode('utf-8'),
                        100000,
                        16)  
        h_bin = bin(int.from_bytes(h2, byteorder=sys.byteorder))
        h2_bin = bin(int.from_bytes(h2, byteorder=sys.byteorder))
        h_bin=h_bin[2:]
        h2_bin=h2_bin[2:]                                

        payload = {"Clientchallenge": Clientchallenge}
        url = "http://127.0.0.1:10010/authenticate"
        r = requests.post(url, data=payload)
        return
        


    @cherrypy.expose
    def response2(self,Serverchallenge):

        global h_bin,h2_bin
        Clientchallenge= ''.join(random.choices(STRING.ascii_lowercase +
                                    STRING.ascii_uppercase + 
                                    STRING.digits,
                                    k = 16))
        
        h = pbkdf2_hmac("sha256",
                        current_auth_pass.encode('utf-8'),
                        (Serverchallenge + Clientchallenge).encode('utf-8'),
                        100000,
                        16)

        h2 = pbkdf2_hmac("sha256",
                        current_auth_pass.encode('utf-8'),
                        (Clientchallenge + Serverchallenge).encode('utf-8'),
                        100000,
                        16)  
        h_bin = bin(int.from_bytes(h2, byteorder=sys.byteorder))
        h2_bin = bin(int.from_bytes(h2, byteorder=sys.byteorder))
        h_bin=h_bin[2:]
        h2_bin=h2_bin[2:]                                

        payload = {"Clientchallenge": Clientchallenge}
        url = "http://127.0.0.1:10010/authenticate2"
        r = requests.post(url, data=payload)       
        return  
        
    @cherrypy.expose
    def getc(self,c1,c2,iv,salt): 
        global check
        global current_username
        global current_password

        key = generate_key(current_auth_pass, "AES-128", b64decode(salt.encode('utf-8')))         
    
        decrypted_user = decrypt(b64decode(c1.encode('utf-8')), key, "AES-128", b64decode(iv.encode('utf-8')))
        unpadded_user = unpadder(decrypted_user, "AES-128")

        decrypted_senha = decrypt(b64decode(c2.encode('utf-8')), key, "AES-128", b64decode(iv.encode('utf-8')))
        unpadded_senha = unpadder(decrypted_senha, "AES-128")
        

        current_username = unpadded_user.decode('utf-8')
        current_password = unpadded_senha.decode('utf-8')
        return
    
    @cherrypy.expose
    def validate(self,b): 
        global pos
        global h2_bin
        global flag
        bit = bin(int(b))
        if bit[2] == h2_bin[pos] and flag==1:
            print("OK client")
            b = h_bin[pos]
            payload = {"b": str(b)}
            url = "http://127.0.0.1:10010/validate"
            r = requests.post(url, data=payload)
        else:
            print("NOT OK")
            b = random.randint(0, 1)
            payload = {"b": str(b)}
            url = "http://127.0.0.1:10010/validate"
            r = requests.post(url, data=payload)
            flag=0   
        pos = pos +1   
        return




    @cherrypy.expose
    def addUser(self,user,password,password2):
        
        with sqlite3.connect(string) as conn:
            comand = conn.execute("SELECT * FROM users WHERE user=?",[user])
            data = comand.fetchall()
            if data!=[]:
                linha = """
							<p>Nome de utilizador já existe.Tente outra vez.</p>
							
                            
					"""    
                return open('passError.html','r').read().format(linha) #utilizador já existe
            if password == password2:
                comand=conn.execute("INSERT into users(user,password,balance) values (?,?,?)",[user, password, 0])
        return open('index.html','r').read() 
        
    

    @cherrypy.expose
    def shop(self,user=current_username,password=current_password):
        global current_user
        global current_username
        global current_password
        if current_username!="" and current_password!="":
            user = current_username
            password = current_password
        with sqlite3.connect(string) as conn:
            comand = conn.execute("SELECT * FROM users WHERE user=? AND password=?",[user,password])  #assim, tira a vulnerabilidade de entrar sem saber login e pass
            data = comand.fetchall()
            
            if data!=[]: 
                
                current_user = data[0][0]  # guarda o id do utilizador que fez login
                current_username=data[0][1]
                current_password = data[0][2]
                return open('shop.html','r').read()
            else :
                
                linha = """
							<p>User ou password inválido. Tente outra vez.</p>
							
                            
						"""
                return open('indexErro.html','r').read().format(linha)

    @cherrypy.expose
    def password(self):
        return open('password.html','r').read()
    @cherrypy.expose
    def reclamacao(self):
        return open('reclamacoes.html','r').read()
    
    @cherrypy.expose
    def sendReport(self,ficheiro):
        
        if ((str(ficheiro.content_type) == "image/jpeg") or (str(ficheiro.content_type) == "image/jpg") or (str(ficheiro.content_type) == "image/png")):
            dir = os.path.dirname(__file__)
            nome = ficheiro.filename
            f = os.path.normpath(os.path.join(dir,nome))
            with sqlite3.connect(string) as conn:
                comand = conn.execute("INSERT into files (user,file) values(?,?)",[current_user,nome])
            with open(f,'wb') as out:
                while True:
                    aux = ficheiro.file.read(8192)
                    if not aux:
                        break
                    out.write(aux)
            out = """
				    <p>Submissão concluída</p>
							
                            
			        """
        else:
            out = """
				    <p>Submissão falhada. Ficheiro enviado tem de ser uma imagem.(.jpg ou .jpeg ou .png)</p>
							
                            
			        """
        return open('reclamacoes_out.html','r').read().format(out)
    @cherrypy.expose
    def alterar_senha(self,user_name,last_password,new_password):
        with sqlite3.connect(string) as conn:
            comand = conn.execute("SELECT * FROM users WHERE user =?",[user_name])
            data = comand.fetchall()
            if data == [] or user_name != current_username or current_password != last_password:
                linha = """
							<p>Utilizador ou password errada.</p>
							
                            
					"""   
                return open('passwordAlterada.html','r').read().format(linha)
            user_balance = data[0][3]
        with sqlite3.connect(string) as conn:
            r = conn.execute("REPLACE into users(user_id,user,password,balance) values (?,?,?,?)",[data[0][0],user_name,new_password,user_balance])
            linha = """
							<p>Password alterada com sucesso.</p>
							
                            
					"""    
        return open('passwordAlterada.html','r').read().format(linha)
        
    @cherrypy.expose
    def addProduct(self,product,quantity):
        quantity = abs(int(quantity)) 
        with sqlite3.connect(string) as conn:
            comand = conn.execute("SELECT * FROM products WHERE name=?",[product])
            data = comand.fetchall()
            product_id = data[0][0]
            price = data[0][2]
            comand = conn.execute("SELECT * FROM orders WHERE product=? AND client=?",[product_id,current_user])
            data = comand.fetchall()
            if data!=[]:
                quantidade = data[0][3] + quantity
            else:
                quantidade=quantity    
            
            comand = conn.execute("REPLACE into orders(client,product,quantity) values (?,?,?)",[current_user,product_id,quantidade])  
            comand = conn.execute("SELECT * FROM users WHERE user_id=?",[current_user])
            data = comand.fetchall()
            balance=data[0][3]
            balance=balance+(price*-1)*quantity  #nas compras o saldo será subtraído (price*-1)
            comand = conn.execute("UPDATE users SET balance = ? WHERE user_id = ?",[balance,current_user])  
            return open('shop.html','r').read() 

   
    @cherrypy.expose
    def showProducts(self):
        with sqlite3.connect(string) as conn:
            comand = conn.execute("SELECT * FROM orders WHERE client=?",[current_user])
            data = comand.fetchall()
            out = ""
            
        with sqlite3.connect(string) as conn:

            for row in data:
                product_id = row[2]
                quantity = row[3]
                with sqlite3.connect(string) as conn:
                    comand = conn.execute("SELECT * FROM products WHERE product_id=?",[product_id])
                    l = comand.fetchall()
                    for row in l:
                        product = row[1]
                        out += """      
                                        
                                            <h3> Produto: %s </h3> 
                                            
                                            <h3>  %s </h3>
                                            
                                        
                                        
                                    """%(product,quantity)
        with sqlite3.connect(string) as conn:
            comand = conn.execute("SELECT * FROM users WHERE user_id=?",[current_user])
            data = comand.fetchall()
            out1 = ""
            balance = data[0][3]
            out1 = """      
                                        
                                            <h3>  %s$ </h3> 
                                            
                                           
                                            
                                        
                                        
                                    """%(balance)
        return open('carrinho.html','r').read().format(out,out1)

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

if __name__ == '__main__':

    cherrypy.server.socket_port = 8080
    cherrypy.config.update({'server.socket_port': 8080,
                            'server.ssl_module':'builtin'})
    cherrypy.quickstart(App(),'/',conf)

