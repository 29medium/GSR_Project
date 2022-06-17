from Crypto.Cipher import AES
from socket import *


def do_encrypt(message):
    obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
    ciphertext = obj.encrypt(message)
    return ciphertext

def do_decrypt(ciphertext):
    obj2 = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
    message = obj2.decrypt(ciphertext)
    return message

def main():
    HOST = "localhost"
    PORT = 65432

    s = socket()
    s.connect((HOST,PORT))

    #data = do_encrypt("192.168.1.68,public,1.3.6.1.2.1.1.1.0")
    #s.sendAll(data)

    data = bytes("192.168.1.68,public,1.3.6.1.2.1.1.1.0", encoding='utf8')
    s.sendall(data)

    # print(do_decrypt(s.recv()))
    data = s.recv(1024).decode('utf8')
    print(data)

main()