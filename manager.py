import threading
from socket import *
import time


requests = set()
request_number = 0
lock = threading.Lock()

def get_request_number():
    global request_number
    
    request_number += 1
    return str(request_number)

def ask_responses(s):
    global requests, lock

    while True:
        time.sleep(5)

        lock.acquire()
        for r in requests:
            data = bytes("get_response," + r, encoding='utf8')
            s.sendall(data)
            time.sleep(0.5)
        lock.release()

def receive_responses(s):
    global requests

    while True:
        data = s.recv(1024).decode('utf8')

        print(data)

        l = data.split(",")

        snmp_type = l[0]
        request_number = l[1]

        if snmp_type=="response":
            response_type = l[2]

            if response_type=="true":
                lock.acquire()
                requests.remove(request_number)
                lock.release()

                for elem in l[3:]:
                    print(elem)

            elif response_type=="error":
                lock.acquire()
                requests.remove(request_number)
                lock.release()

                print(l[3])

        elif snmp_type=="ack":
            requests.add(request_number)

        else:
            s.close()

def main():
    global request_number

    HOST = "localhost"
    PORT = 65432

    s = socket()
    s.connect((HOST,PORT))

    threading.Thread(target=receive_responses, args=[s]).start()
    threading.Thread(target=ask_responses, args=[s]).start()

    data = bytes("get," + get_request_number() + ",192.168.1.68,public,1.3.6.1.2.1.1.1.0", encoding='utf8')
    s.sendall(data)

    time.sleep(0.5)

    data = bytes("get_next," + get_request_number() + ",192.168.1.68,public,1.3.6.1.2.1.1.1.0", encoding='utf8')
    s.sendall(data)

    time.sleep(0.5)

    data = bytes("get_bulk," + get_request_number() + ",192.168.1.68,public,0,10,1.3.6.1.2.1.1.3.0", encoding='utf8')
    s.sendall(data)

    while True:
        type = input("Insert type")
        ip = input("Insert host")
        community = input("Insert community string")
        oids = input("Insert oids seperated by comma")

        if(type=="get_bulk"):
            nonRepeaters = input("Insert non repeaters")
            maxRepetitions = input("Insert max repetitions")
            
            data = bytes(type + "," + get_request_number() + ',' + ip + "," + community + "," + nonRepeaters + "," + maxRepetitions + ',' + oids, encoding='utf8')
            s.sendall(data) 
        else:
            data = bytes(type + "," + get_request_number() + ',' + ip + "," + community + "," + oids, encoding='utf8')
            s.sendall(data) 

main()