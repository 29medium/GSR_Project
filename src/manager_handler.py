from requests import request
from encrypt import DH
from pysnmp.hlapi import *
from threading import Thread

# Classe responsável por atender um manager
class ManagerHandler(Thread):
    # inicialização da classe ManagerHandler
    def __init__(self, conn, addr, shared_key, requestsTable, lock, counter):
        self.conn = conn
        self.address = addr
        self.shared_key = shared_key
        self.requestsTable = requestsTable
        self.lock = lock
        self.counter = counter

        Thread.__init__(self)
    
    # Função que recebe o pedido SNMP do agente e verifica se ocorreu algum erro
    def fetch(self, handler):  
        error_indication, error_status, error_index, var_binds = next(handler)

        if not error_indication and not error_status:
            return var_binds[0][1]

    # Função que adiciona nova linha à tabela da MIBsec
    def addRequestsTable(self, idOper, typeOper, idSource, idDestination, oidArg, valueArg):
        with self.lock:
            self.requestsTable[idOper] = [typeOper,idSource,idDestination,oidArg,valueArg,"STRING",len(bytes(valueArg))]

    # Função executada ao arrancar a Thread. Trata dos pedidos efetuados pelo manager
    def run(self):
        try:
            while True:
                data = DH.recv(self.conn, self.shared_key)

                l = data.split(",")

                typeOper = l[0]

                # Verifica se o pedido é get ou get_next
                if typeOper in ["get","get_next"]:
                    host = l[1]
                    com_str = l[2]
                    oids = l[3:]

                    for oid in oids:   
                        # Faz pedido ao agente
                        if typeOper=="get":
                            valueArg = self.fetch(getCmd(
                                SnmpEngine(), CommunityData(com_str, mpModel=1),
                                UdpTransportTarget((host, 161)),
                                ContextData(), ObjectType(ObjectIdentity(oid))
                            ))
                        else:
                            valueArg = self.fetch(nextCmd(
                                SnmpEngine(), CommunityData(com_str, mpModel=1),
                                UdpTransportTarget((host, 161)),
                                ContextData(), ObjectType(ObjectIdentity(oid))
                            ))

                        # Envia ack ao manager
                        idOper = self.counter.value()
                        DH.send("ack," + str(idOper), self.conn, self.shared_key)

                        # Adiciona resultado à tabela
                        self.addRequestsTable(idOper, typeOper, self.address, host, oid, valueArg)

                # Verifica se o pedido é response
                elif typeOper=="response":
                    oid = l[1]
                    parcels = oid.split(".")

                    # Verifica os campos do oid e envia valores pedidos
                    if len(parcels) == 2 and int(parcels[0])==1:
                        idOper = int(parcels[1])

                        with self.lock:
                            if idOper in self.requestsTable and self.address == self.requestsTable[idOper][1]:
                                msg = "requestsTable.idOper = " + parcels[1]
                                msg += "\nrequestsTable.typeOper = " + self.requestsTable[idOper][0]
                                msg += "\nrequestsTable.idSource = " + self.requestsTable[idOper][1][0] + " " + str(self.requestsTable[idOper][1][1])
                                msg += "\nrequestsTable.idDestination = " + self.requestsTable[idOper][2]
                                msg += "\nrequestsTable.oidArg = " + self.requestsTable[idOper][3]
                                msg += "\nrequestsTable.valueArg = " + str(self.requestsTable[idOper][4])
                                msg += "\nrequestsTable.typeArg = " + self.requestsTable[idOper][5]
                                msg += "\nrequestsTable.sizeArg = " + str(self.requestsTable[idOper][6])

                                DH.send(msg, self.conn, self.shared_key)
                            else:
                                DH.send("Opertaion not available", self.conn, self.shared_key)
                    elif len(parcels) == 3 and int(parcels[1])>=1 and int(parcels[1])<=8 and int(parcels[0])==1:
                        n = int(parcels[1])
                        idOper = int(parcels[2])
                        with self.lock:
                            if idOper in self.requestsTable and self.address == self.requestsTable[idOper][1]:
                                if n == 1:
                                    DH.send("requestsTable.idOper = " + parcels[1], self.conn, self.shared_key)
                                elif n==2:
                                    DH.send("requestsTable.typeOper = " + self.requestsTable[idOper][0], self.conn, self.shared_key)
                                elif n==3:
                                    DH.send("requestsTable.idSource = " + self.requestsTable[idOper][1][0] + " " + str(self.requestsTable[idOper][1][1]), self.conn, self.shared_key)
                                elif n==4:
                                    DH.send("requestsTable.idDestination = " + self.requestsTable[idOper][2], self.conn, self.shared_key)
                                elif n==5:
                                    DH.send("requestsTable.oidArg = " + self.requestsTable[idOper][3], self.conn, self.shared_key)
                                elif n==6:
                                    DH.send("requestsTable.valueArg = " + str(self.requestsTable[idOper][4]), self.conn, self.shared_key)
                                elif n==7:
                                    DH.send("requestsTable.typeArg = " + self.requestsTable[idOper][5], self.conn, self.shared_key)
                                elif n==8:
                                    DH.send("requestsTable.sizeArg = " + str(self.requestsTable[idOper][6]), self.conn, self.shared_key)
                            else:
                                DH.send("Opertaion not available", self.conn, self.shared_key)
                    else:
                        DH.send("Invalid oid", self.conn, self.shared_key)
        
        except IndexError:
            print("Conexão interrompida")
            self.conn.close()
        
        except KeyboardInterrupt:
            self.conn.close()