from threading import Thread
from encrypt import DH

class Sender(Thread):
    def __init__(self, conn, shared_key, requests, lock):
        self.conn = conn
        self.shared_key = shared_key
        self.request_number = 0
        self.requests = requests
        self.lock = lock

        Thread.__init__(self)

    def readOption(max):
        result = -1

        while result<=0 or result>max:
            print("\n----------------------------------")
            print(" 1 | Mostrar resultados")
            print(" 2 | Executar pedidos")
            print(" 3 | Executar pedidos predefinidos")
            print("----------------------------------")

            try:
                result = int(input(" Escolha uma opção >> "))
            except ValueError:
                result = -1
        
        return result

    def get_request_number(self):
        self.request_number += 1
        return str(self.request_number)

    def run(self):
        while True:
            option = Sender.readOption(3)

            if option==1:
                if not self.requests:
                    print("\nNão existem ainda resultados de pedidos")
                else:
                    print("\nResultados:")
                    for req_number in self.requests:
                        if self.requests[req_number][1] != None:
                            print("\n" + str(req_number) + " | " + self.requests[req_number][0])

                            if isinstance(self.requests[req_number][1], list):
                                for elem in self.requests[req_number][1]:
                                    print("    " + elem)
                            else:
                                print("    " + self.requests[req_number][1])
            
            elif option==2:
                type = input(" Inserir tipo (get/get_next/get_bulk) >> ")
                if(type in ["get","get_next","get_bulk"]):
                    req = self.get_request_number()

                    ip = input(" Inserir host >> ")
                    community = input(" Inserir community string >> ")
                    oids = input(" Inserir oids separados por virgula >> ")

                    if(type=="get_bulk"):
                        nonRepeaters = input(" Inserir non repeaters >> ")
                        maxRepetitions = input(" Inserir max repetitions >> ")
                        
                        msg = type + "," + req + ',' + ip + "," + community + "," + nonRepeaters + "," + maxRepetitions + ',' + oids
                    else:
                        msg = type + "," + req + ',' + ip + "," + community + "," + oids

                    with self.lock:
                        self.requests[req] = [msg , None]

                    DH.send(msg, self.conn, self.shared_key)

                    print("\nPedido efetuado")
                else:
                    print("\nPedido não efetuado. Tipo incorreto")
            
            if option==3:
                req = self.get_request_number()
                msg = "get," + req + ",192.168.1.68,public,1.3.6.1.2.1.1.1.0"
                with self.lock:
                        self.requests[req] = [msg , None]
                DH.send(msg, self.conn, self.shared_key)
                
                req = self.get_request_number()
                msg = "get_next," + req + ",192.168.1.68,public,1.3.6.1.2.1.1.1.0"
                with self.lock:
                        self.requests[req] = [msg , None]
                DH.send(msg, self.conn, self.shared_key)
                
                req = self.get_request_number()
                msg = "get_bulk," + req + ",192.168.1.68,public,0,10,1.3.6.1.2.1.1.3.0"
                with self.lock:
                        self.requests[req] = [msg , None]
                DH.send(msg, self.conn, self.shared_key)

                print("\nPedidos efetuados")
