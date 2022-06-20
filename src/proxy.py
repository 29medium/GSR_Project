import socket
from threading import Thread
from pysnmp.hlapi import *
from encrypt import DH, EncryptError, AuthenticationEncryptError
from manager_handler import ManagerHandler
import sys
import json

class Proxy:
    def __init__(self):
        self.ss = None
        self.HOST = "localhost"
        self.PORT = 65432
        self.password = None
        self.managers = None

    def run(self):
        args = sys.argv
        argc = len(args) - 1

        if argc != 1:
            print("Numero de argumentos errado. Esperado 1, Obtido " + str(argc))
            return

        self.password = args[1]
        self.managers = json.load(open("../files/managers.json"))

        self.ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ss.bind((self.HOST, self.PORT))
        self.ss.listen(5)

        try:
            while True:
                conn, addr = self.ss.accept()
                
                try:
                    shared_key = DH.connection(conn)
                    DH.authentication_proxy(conn, self.password, self.managers, shared_key)
                    manager = ManagerHandler(conn, addr, shared_key)
                    manager.daemon = True
                    manager.start()

                except AuthenticationEncryptError:
                    print("Erro na autenticação")
                    conn.close()

                except EncryptError:
                    print("Erro a estabelecer ligação com o manager")
                    conn.close()
            
        except KeyboardInterrupt:
            print("Conexão terminada")

proxy = Proxy()
proxy.run()