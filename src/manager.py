import json
from threading import Lock
from encrypt import DH, EncryptError, AuthenticationEncryptError
from sender import Sender
from receiver import Receiver
from scheduler import Scheduler
from socket import *
import sys
class Manager:
    def __init__(self):
        self.HOST = "localhost"
        self.PORT = 65432
        self.conn = None
        self.user_name = None
        self.password = None
        self.proxy_password = None
        self.shared_key = None
        self.requests = dict()
        self.lock = Lock()        

    def run(self):
        args = sys.argv
        argc = len(args) - 1

        if argc != 2:
            print("Numero de argumentos errado. Esperado 2, Obtido " + str(argc))
            return

        self.user_name = args[1]
        self.password = args[2]
        self.proxy_password = json.load(open("../files/proxy.json"))['proxy']

        try:
            self.conn = socket()
            self.conn.connect((self.HOST, self.PORT))

            self.shared_key = DH.connection(self.conn)

            DH.authentication_manager(self.conn, self.user_name, self.password, self.proxy_password, self.shared_key)

            sender = Sender(self.conn, self.shared_key, self.requests, self.lock)
            receiver = Receiver(self.conn, self.shared_key, self.requests, self.lock)
            scheduler = Scheduler(self.conn, self.shared_key, self.requests, self.lock)

            sender.daemon = True
            receiver.daemon = True
            scheduler.daemon = True

            sender.start()
            receiver.start()
            scheduler.start()

            receiver.join()
            print("\nConexão interrompida")
            self.conn.close()

        except AuthenticationEncryptError:
            print("Erro na autenticação")
            self.conn.close()

        except EncryptError:
            print("\nErro a estabelecer ligação com o proxy")
            self.conn.close()

        except ConnectionRefusedError:
            print("\nProxy indiponível")

        except KeyboardInterrupt:
            print("\nConexão terminada")

manager = Manager()
manager.run()