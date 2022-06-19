from threading import Lock
from encrypt import DH
from sender import Sender
from receiver import Receiver
from scheduler import Scheduler
from socket import *

class Manager:
    def __init__(self):
        self.conn = None
        self.shared_key = None
        self.requests = set()
        self.lock = Lock()        

    def run(self):
        HOST = "localhost"
        PORT = 65432

        self.conn = socket()
        self.conn.connect((HOST,PORT))

        try:
            self.shared_key = DH.connection(self.conn)

            sender = Sender(self.conn, self.shared_key)
            receiver = Receiver(self.conn, self.shared_key, self.requests, self.lock)
            scheduler = Scheduler(self.conn, self.shared_key, self.requests, self.lock)

            sender.start()
            receiver.start()
            scheduler.start()
            
        except ConnectionError:
            print("Connection error")
            self.conn.close()

manager = Manager()
manager.run()