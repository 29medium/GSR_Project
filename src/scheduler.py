from threading import Thread
from encrypt import DH
import time

class Scheduler(Thread):
    def __init__(self, conn, shared_key, requests, lock):
        self.conn = conn
        self.shared_key = shared_key
        self.requests = requests
        self.lock = lock

        Thread.__init__(self)

    def run(self):
        while True:
            time.sleep(5)
            with self.lock:
                for r in self.requests:
                    DH.send("get_response," + r, self.conn, self.shared_key)