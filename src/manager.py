from threading import Lock
from encrypt import DH, EncryptError
from sender import Sender
from receiver import Receiver
from scheduler import Scheduler
from socket import *

class Manager:
    def __init__(self):
        self.HOST = "localhost"
        self.PORT = 65432
        self.conn = None
        self.shared_key = None
        self.requests = dict()
        self.lock = Lock()        

    def run(self):
        try:
            self.conn = socket()
            self.conn.connect((self.HOST, self.PORT))

            self.shared_key = DH.connection(self.conn)

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
                
        except EncryptError:
            print("\nErro a estabelecer ligação com o proxy")
            self.conn.close()

        except ConnectionRefusedError:
            print("\nProxy indiponível")

        except KeyboardInterrupt:
            print("\nConexão terminada")
            #self.conn.close()

manager = Manager()
manager.run()