from ctypes import cast
from socket import socket
import schedule, csv, time
from pysnmp.hlapi import *

def fetch(handler, count):
    result = []
    for i in range(count):
        try:
            error_indication, error_status, error_index, var_binds = next(handler)
            if not error_indication and not error_status:
                items = {}
                for var_bind in var_binds:
                    items[str(var_bind[0])] = var_bind[1]
                result.append(items)
            else:
                raise RuntimeError('Got SNMP error: {0}'.format(error_indication))
        except StopIteration:
            break

    return result

def poll(host, com_str, mib):
    handler = getCmd(
        SnmpEngine(),
        CommunityData(com_str, mpModel=0),
        UdpTransportTarget((host, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(mib))
    )

    print(fetch(handler, 1))

with open("inventory.csv") as inventory:
    invcsv = csv.reader(inventory)

    for row in invcsv:
        host = row[0]
        freq = int(row[1])
        com_str = row[2]
        
        for mib in row[3:]:
            poll(host, com_str, mib)