from threading import Thread
from encrypt import DH

class Receiver(Thread):
    def __init__(self, conn, shared_key, requests, lock):
        self.conn = conn
        self.shared_key = shared_key
        self.requests = requests
        self.lock = lock

        Thread.__init__(self)

    def run(self):
        while True:
            data = DH.recv(self.conn, self.shared_key)

            l = data.split(",")

            snmp_type = l[0]
            request_number = l[1]

            if snmp_type=="response":
                response_type = l[2]

                if response_type=="true":
                    with self.lock:
                        self.requests[request_number][1] = l[3:]

                elif response_type=="error":
                    with self.lock:
                        self.requests[request_number][1] = "Error"