#!/usr/bin/python
from socket import *
from binascii import *
from random import *
from struct import *

# local machine mac address
chaddr = unhexlify('001122334455')

# allowed dhcp servers
whitelist = set(['192.168.1.1'])

# random session id (xid)
xid = pack('L', randrange(0, 2**32 - 1 ))

# setup socket
s = socket(AF_INET, SOCK_DGRAM)
s.bind(('0.0.0.0', 68))
s.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

request = \
    '\x01\x01\x06\x00' \
    + xid \
    + ''.ljust(20, '\x00') \
    + chaddr.ljust(16, '\x00') \
    + ''.ljust(192, '\x00') \
    + '\x63\x82\x53\x63' \
    + '\x35\x01\x03' \
    + '\xff'
s.sendto(request, ('255.255.255.255', 67))

# listen for dhcp packets for max 2.5 seconds
status = "OK - No rogue dhcp servers detected"
r = 0
s.settimeout(2.5)
while 1:
    try:
        buf, (ip, port) = s.recvfrom(65565)
    except:
        break
    opcode, = unpack_from('B', buf)
    if not (ip in whitelist and opcode == 0x02):
        r = 2
        status = "CRITICAL - Rogue dhcp server detected on IP-addr: " + ip
        break

s.close()
print status
exit(r)


