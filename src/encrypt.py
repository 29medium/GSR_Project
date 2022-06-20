import os
from pickle import FALSE
from cryptography.exceptions import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PrivateKey

class AuthenticationEncryptError(Exception):
    pass

class EncryptError(Exception):
    pass

class X448_keys:
    def generate_private_key(self):
        private_key = X448PrivateKey.generate()
        return private_key

    def generate_public_key(self,private_key):
        public_key = private_key.public_key()
        return public_key

    def serialize_public_key(self, public_key):
        return public_key.public_bytes( 
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

    def deserialize_public_key(self, public_key):
        return serialization.load_pem_public_key(public_key,backend = default_backend())

    def generate_shared_key(self,private_key,other_public_key):
        shared_key = private_key.exchange(other_public_key)
        return shared_key

class Ed448_keys:
    def generate_private_key(self):
        private_key = Ed448PrivateKey.generate()
        return private_key

    def generate_public_key(self,private_key):
        public_key = private_key.public_key()
        return public_key

    def serialize_public_key(self, public_key):
        return public_key.public_bytes( 
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        
    def deserialize_public_key(self, public_key):
        return serialization.load_pem_public_key(public_key,backend = default_backend())

    def generate_signature(self,ed_private_key,public_key):
        signature = ed_private_key.sign(public_key)
        return signature

    def verify_signature(self,peer_public_key,signature,message):
        peer_public_key.verify(signature,message)

class DH:
    def hashs(s):
        digest = hashes.Hash(hashes.SHA256(),backend=default_backend())
        digest.update(s)
        return digest.finalize()

    def conn_send(conn, msg):
        size = str(len(msg)).encode('utf8')
        conn.sendall(size)

        conn.sendall(b'\n')

        x = bytearray(msg)
        conn.sendall(x)
        
    def conn_recv(conn):
        buffer = bytearray()
        flag = True

        while flag:
            recv = bytearray(conn.recv(1))

            if recv != b'\n':
                buffer.append(recv[0])
            else:
                flag = False

        size = int(bytes(buffer).decode('utf8'))
        recv = conn.recv(size)
        
        return recv

    def send(str, conn, shared_key):
        chacha = ChaCha20Poly1305(shared_key)
        
        nonce=os.urandom(12)
        cipher_text = chacha.encrypt(nonce, str.encode('utf8'), None)

        DH.conn_send(conn, cipher_text)

        DH.conn_send(conn, nonce)

    def recv(conn, shared_key):
        cipher_text = DH.conn_recv(conn)
        nonce = DH.conn_recv(conn)

        chacha = ChaCha20Poly1305(shared_key)
        
        bytes = chacha.decrypt(nonce, cipher_text, None)
        data = bytes.decode('utf8')

        return data

    def authentication_proxy(conn, password, managers, shared_key):
        # Verificação da password do manager
        peer_user_name = DH.recv(conn, shared_key)
        peer_password = DH.recv(conn, shared_key)
        
        auth = True
        if peer_user_name not in managers:
            auth = False
        else:
            if managers[peer_user_name] != peer_password:
                auth = False

        DH.send(str(auth), conn, shared_key)
        
        # Verificação da password do proxy
        DH.send(password, conn, shared_key)
        peer_auth = DH.recv(conn, shared_key) == 'True'

        # Confirmação final
        if not (auth and peer_auth):
            raise AuthenticationEncryptError
        

    def authentication_manager(conn, user_name, password, proxy_password, shared_key):
        # Verificação da password do manager
        DH.send(user_name, conn, shared_key)
        DH.send(password, conn, shared_key)
        peer_auth = DH.recv(conn, shared_key) == 'True'
        
        # Verificação da password do proxy
        auth = True
        peer_password = DH.recv(conn, shared_key)
        if peer_password != proxy_password:
            auth = False
        DH.send(str(auth), conn, shared_key)

        # Confirmação final
        if not (auth and peer_auth):
            raise AuthenticationEncryptError

    def connection(conn):
        x448 = X448_keys()
        ed448 = Ed448_keys()

        #private e public key x448
        private_key_x448 = x448.generate_private_key() 
        public_key_x448 = x448.generate_public_key(private_key_x448)
        
        #private e public key ed448
        private_key_ed448 = ed448.generate_private_key()
        public_key_ed448 = ed448.generate_public_key(private_key_ed448)

        #serealizar public keys
        public_key_ed448_bytes = ed448.serialize_public_key(public_key_ed448)
        public_key_x448_bytes = x448.serialize_public_key(public_key_x448)

        #Assinatura
        signature = ed448.generate_signature(private_key_ed448,public_key_x448_bytes)

        #envio das chaves e assinatura
        DH.conn_send(conn, public_key_x448_bytes)
        peer_public_key_x448_bytes = DH.conn_recv(conn)

        DH.conn_send(conn, public_key_ed448_bytes)
        peer_public_key_ed448 = ed448.deserialize_public_key(DH.conn_recv(conn))

        DH.conn_send(conn, signature)
        peer_signature = DH.conn_recv(conn)
        
        #Verificação da assinatura do recetor
        try:
            ed448.verify_signature(peer_public_key_ed448,peer_signature,peer_public_key_x448_bytes)
        except InvalidSignature:
            raise ConnectionError

        #Cálculo da chave partilhada
        peer_public_key_x448 = x448.deserialize_public_key(peer_public_key_x448_bytes)
        shared_key = x448.generate_shared_key(private_key_x448,peer_public_key_x448)

        #Confirmação
        tag = DH.hashs(bytes(shared_key))
        conn.send(tag)
        other_tag = conn.recv(1024)

        if tag != other_tag:
            raise ConnectionError

        #derivação da chave
        try:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                )
            derived_key = hkdf.derive(shared_key)

            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'handshake data',
                )
            hkdf.verify(shared_key, derived_key)
        except:
            raise ConnectionError('Falha na derivação')

        return derived_key