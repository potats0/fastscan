#!/bin/env python
# -*- coding:UTF-8 -*-
from ip_parse import prase_package
from scan_config import Scan_Config
from super_scan_c import rawsock_recv_packet
from super_scan_c.SuperScan_C import pcap_close
from utils import ip2int


def receive_thread(scan_config: Scan_Config):
    while True:
        if scan_config.kill:
            break
        else:
            pk = rawsock_recv_packet(scan_config.pcap)
            if pk:
                # 抓包不成功的情况下可能返回none
                pk = prase_package(pk)
                if "tcp" in pk:
                    ip_header = pk['ip_header']
                    tcp_header = pk['tcp']
                    cookie = scan_config.packet.syn_cookie(ip2int(ip_header['src_ip']), tcp_header['src_port'],
                                                           ip2int(ip_header['dst_ip']), tcp_header['dst_port'])
                    if tcp_header['ack_num'] - 1 == cookie:
                        if tcp_header['flags']['SYN'] and tcp_header['flags']['ACK']:
                            # adapter.output(pk)
                            print(f"{ip_header['src_ip']}:{tcp_header['src_port']}")
                        elif tcp_header['flags']['RST']:
                            pass
                elif 'arp' in pk:
                    """
                    如果对方发送arp请求，建议回复一下
                    但是目前来讲，都是使用半系统tcp 栈，所以我们暂时不处理
                    """
                    pass
    pcap_close(scan_config.pcap)
