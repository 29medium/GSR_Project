from threading import Thread
from encrypt import DH

class Sender(Thread):
    def __init__(self, conn, shared_key):
        self.conn = conn
        self.shared_key = shared_key
        self.request_number = 0

        Thread.__init__(self)

    def get_request_number(self):
        self.request_number += 1
        return str(self.request_number)

    def run(self):
        DH.send("get," + self.get_request_number() + ",192.168.1.68,public,1.3.6.1.2.1.1.1.0", self.conn, self.shared_key)
        DH.send("get_next," + self.get_request_number() + ",192.168.1.68,public,1.3.6.1.2.1.1.1.0", self.conn, self.shared_key)
        DH.send("get_bulk," + self.get_request_number() + ",192.168.1.68,public,0,10,1.3.6.1.2.1.1.3.0", self.conn, self.shared_key)

        while True:
            type = input("Insert type >>")
            ip = input("Insert host >>")
            community = input("Insert community string >>")
            oids = input("Insert oids seperated by comma >>")

            if(type=="get_bulk"):
                nonRepeaters = input("Insert non repeaters >>")
                maxRepetitions = input("Insert max repetitions >>")
                
                DH.send(type + "," + self.get_request_number() + ',' + ip + "," + community + "," + nonRepeaters + "," + maxRepetitions + ',' + oids, self.conn, self.shared_key)
            else:
                DH.send(type + "," + self.get_request_number() + ',' + ip + "," + community + "," + oids, self.conn, self.shared_key)
