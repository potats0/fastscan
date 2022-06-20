# -*- coding:UTF-8 -*-
import socket
import struct


def ip2int(ip):
    return socket.ntohl(struct.unpack("I", socket.inet_aton(str(ip)))[0])


def int2ip(int_ip):
    return socket.inet_ntoa(struct.pack('I', socket.htonl(int_ip)))
