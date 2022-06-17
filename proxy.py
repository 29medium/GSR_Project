import socket
from threading import Thread
from pysnmp.hlapi import *
from Crypto.Cipher import AES

def do_encrypt(message):
    obj = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
    ciphertext = obj.encrypt(message)
    return ciphertext

def do_decrypt(ciphertext):
    obj2 = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
    message = obj2.decrypt(ciphertext)

    return str(message)

def fetch(handler):    
    error_indication, error_status, error_index, var_binds = next(handler)

    if not error_indication and not error_status:
        items = list()

        for var_bind in var_binds:
            items.append(var_bind[1])

    else:
        raise RuntimeError('Got SNMP error: {0}'.format(error_indication))

    return str(items[0])

def clientHandler(conn, addr):
    print ("Manager " + addr[0] + " " + str(addr[1]) + " is connected")

    while True:
        #data = do_decrypt(conn.recv(1024))
        data = conn.recv(1024).decode('utf8')

        l = data.split(",")

        host = l[0]
        com_str = l[1]
        mib = l[2]

        handler = getCmd(
            SnmpEngine(),
            CommunityData(com_str, mpModel=0),
            UdpTransportTarget((host, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(mib))
        )

        #data = do_encrypt(fetch(handler))
        data = bytes(fetch(handler), encoding='utf8')
        conn.sendall(data)

def main():
    HOST = "localhost"
    PORT = 65432

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen()

    while True:
        conn, addr = s.accept()

        Thread(target=clientHandler, args=[conn,addr]).start()

main()