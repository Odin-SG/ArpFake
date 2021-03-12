import socket
from struct import pack
from uuid import getnode as get_mac

def main():
    dest_ip = [10, 7, 31, 99]
    local_mac = [int(("%x" % get_mac())[i:i+2], 16) for i in range(0, len("%x" % get_mac()), 2)]
    local_ip = [int(x) for x in socket.gethostbyname(socket.gethostname()).split('.')]

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket. htons(0x0800))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("eth0",socket.htons(0x0800)))

    ARP_FRAME = [
        pack('!H', 0x0001), # HRD
        pack('!H', 0x0800), # PRO
        pack('!B', 0x06), # HLN
        pack('!B', 0x04), # PLN
        pack('!H', 0x0001), # OP
        pack('!6B', *local_mac), # SHA
        pack('!4B', *local_ip), # SPA
        pack('!6B', *(0x00,)*6), # THA
        pack('!4B', *dest_ip), # TPA
    ]
    print(ARP_FRAME)
    sock.sendto(b''.join(ARP_FRAME), ('255.255.255.255', 0))
    sock.close()

if __name__ == "__main__":
    main()