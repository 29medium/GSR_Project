from encrypt import DH
from pysnmp.hlapi import *
from threading import Thread

class ManagerHandler(Thread):
    def __init__(self, conn, addr, shared_key):
        self.conn = conn
        self.address = addr
        self.shared_key = shared_key
        self.requests = dict()

        Thread.__init__(self)
    
    def fetch(self, request_number, handler):  
        error_indication, error_status, error_index, var_binds = next(handler)

        if not error_indication and not error_status:
            
            self.requests[request_number] = list()
            for var_bind in var_binds:
                self.requests[request_number].append(var_bind[1])

        else:
            self.requests[request_number] = 'Got SNMP error: {0}'.format(error_indication)

    def run(self):
        try:
            while True:
                data = DH.recv(self.conn, self.shared_key)

                l = data.split(",")

                snmp_type = l[0]
                request_number = l[1]

                if snmp_type=="get":
                    host = l[2]
                    com_str = l[3]
                    mib = list(map(lambda s : ObjectType(ObjectIdentity(s)), l[4:]))

                    self.fetch(request_number, getCmd(
                        SnmpEngine(),
                        CommunityData(com_str, mpModel=1),
                        UdpTransportTarget((host, 161)),
                        ContextData(),
                        *mib
                    ))

                elif snmp_type=="get_next":
                    host = l[2]
                    com_str = l[3]  
                    mib = list(map(lambda s : ObjectType(ObjectIdentity(s)), l[4:]))

                    self.fetch(request_number, nextCmd(
                        SnmpEngine(),
                        CommunityData(com_str, mpModel=1),
                        UdpTransportTarget((host, 161)),
                        ContextData(),
                        *mib
                    ))

                elif snmp_type=="get_bulk":
                    host = l[2]
                    com_str = l[3]
                    nonRepeaters = int(l[4])
                    maxRepetitions = int(l[5])
                    mib = list(map(lambda s : ObjectType(ObjectIdentity(s)), l[6:]))

                    self.fetch(request_number, bulkCmd(
                        SnmpEngine(),
                        CommunityData(com_str, mpModel=1),
                        UdpTransportTarget((host, 161)),
                        ContextData(),
                        nonRepeaters, maxRepetitions,
                        *mib
                    ))
                
                elif snmp_type=="get_response":
                    if request_number not in self.requests:
                        DH.send("response," + request_number + ",false", self.conn, self.shared_key)
                    elif isinstance(self.requests[request_number], list):
                        for r in self.requests[request_number]:
                            DH.send("response," + request_number + ",true," + str(r), self.conn, self.shared_key)
                    else:
                        DH.send("response," + request_number + ",error," + str(r), self.conn, self.shared_key)
        except IndexError:
            print("Conexão interrompida")
            self.conn.close()
        
        except KeyboardInterrupt:
            self.conn.close()