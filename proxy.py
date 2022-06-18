import socket
from threading import Thread
from pysnmp.hlapi import *
from Crypto.Cipher import AES


results = dict()

def fetch(addr, request_number, handler):  
    error_indication, error_status, error_index, var_binds = next(handler)

    if not error_indication and not error_status:
        if addr not in results:
            results[addr] = dict()

        results[addr][request_number] = list()
        for var_bind in var_binds:
            results[addr][request_number].append(var_bind[1])

    else:
        results[addr][request_number] = 'Got SNMP error: {0}'.format(error_indication)

def clientHandler(conn, addr):
    global results

    print ("Manager " + addr[0] + " " + str(addr[1]) + " is connected")

    while True:
        data = conn.recv(1024).decode('utf8')

        print(data)

        l = data.split(",")

        snmp_type = l[0]
        request_number = l[1]

        if snmp_type=="get":
            host = l[2]
            com_str = l[3]
            mib = list(map(lambda s : ObjectType(ObjectIdentity(s)), l[4:]))

            data = bytes("ack," + request_number, encoding='utf8')
            conn.sendall(data)

            fetch(addr, request_number, getCmd(
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

            data = bytes("ack," + request_number, encoding='utf8')
            conn.sendall(data)

            fetch(addr, request_number, nextCmd(
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

            data = bytes("ack," + request_number, encoding='utf8')
            conn.sendall(data)

            fetch(addr, request_number, bulkCmd(
                SnmpEngine(),
                CommunityData(com_str, mpModel=1),
                UdpTransportTarget((host, 161)),
                ContextData(),
                nonRepeaters, maxRepetitions,
                *mib
            ))
        
        elif snmp_type=="get_response":
            if addr not in results or request_number not in results[addr]:
                data = bytes("response," + request_number + ",false", encoding='utf8')
                conn.sendall(data)
            elif type(results[addr][request_number] is list):
                for r in results[addr][request_number]:
                    data = bytes("response," + request_number + ",true," + str(r), encoding='utf8')
                    conn.sendall(data)
            else:
                data = bytes("response," + request_number + ",error," + str(r), encoding='utf8')
                conn.sendall(data)
        else:
            conn.close()

def main():
    HOST = "localhost"
    PORT = 65432

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen()

    while True:
        conn, addr = s.accept()
        
        Thread(target=clientHandler, args=[conn,addr]).start()

main()