import socket
from threading import Lock
from multiprocessing import RawValue
from pysnmp.hlapi import *
from encrypt import DH, EncryptError, AuthenticationEncryptError
from manager_handler import ManagerHandler
import sys
import json

# classe responsável pelo counter do número de pedidos
class Counter(object):
    def __init__(self):
        self.val = RawValue('i', 0)
        self.lock = Lock()

    def value(self):
        with self.lock:
            self.val.value += 1
            return self.val.value

# classe responsável pela entidade proxy
class Proxy:
    # inicialização da classe proxy
    def __init__(self):
        self.ss = None
        self.HOST = "localhost"
        self.PORT = 65432
        self.password = None
        self.managers = None
        self.requests = dict() # idOper => [ typeOper , idSource , idDestination , oidArg , valueArg , typeArg , sizeArg  ]
        self.lock = Lock()
        self.counter = Counter()
        self.shared_keys = dict() # idSource => shared_key

    # função que atende managers e inicia-lhes uma thread
    def run(self):
        args = sys.argv
        argc = len(args) - 1

        if argc != 1:
            print("Numero de argumentos errado. Esperado 1, Obtido " + str(argc))
            return

        # Dá parse e guarda ficheiro com as passwords dos managers
        self.password = args[1]
        self.managers = json.load(open("../files/managers.json"))

        # Inicia server socket
        self.ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ss.bind((self.HOST, self.PORT))
        self.ss.listen(5)

        try:
            while True:
                conn, addr = self.ss.accept()
                
                try:
                    # cria shared_key
                    shared_key = DH.connection(conn)
                    self.shared_keys[addr] = shared_key
                    # autentica com o manager
                    DH.authentication_proxy(conn, self.password, self.managers, shared_key)
                    # cria e inicia thread managerHandler
                    manager = ManagerHandler(conn, addr, shared_key, self.requests, self.lock, self.counter)
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