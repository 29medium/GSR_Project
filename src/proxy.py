import socket
from threading import Thread
from pysnmp.hlapi import *
from encrypt import ConnectionError
from manager_handler import ManagerHandler

class Proxy:
    def __init__(self):
        self.ss = None
        self.HOST = "localhost"
        self.PORT = 65432

    def run(self):
        self.ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ss.bind((self.HOST, self.PORT))
        self.ss.listen(5)

        while True:
            conn, addr = self.ss.accept()
            
            try:
                manager = ManagerHandler(conn, addr)
                manager.start()

            except ConnectionError:
                print("Connection error")
                conn.close()

proxy = Proxy()
proxy.run()