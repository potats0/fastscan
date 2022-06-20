#!/bin/env python
# -*- coding:UTF-8 -*-
"""
该文件负责重组ipv4报文，构建tcp报文
"""
from random import random

from super_scan_c import rawsock_send_ipv4, template_packet_init, template_set_ttl, siphash24


class Packet:
    def __init__(self, mac_addr, rt_mac_addr, link_type, seed):
        self.px_template = template_packet_init(mac_addr, rt_mac_addr, link_type, seed)
        self.seed = seed

    def set_ttl(self, ttl):
        """
        设置报文的ttl
        :param ttl: 报文ttl
        """
        template_set_ttl(self.px_template, ttl)

    def syn_cookie(self, ip_me, port_me, ip_them, port_them):
        return siphash24(ip_me, port_me, ip_them, port_them, self.seed) & 0x0000FFFF

    def send_tcp_ipv4(self, pcap_pointer, ip_me, port_me, ip_them, port_them, cookie):
        """
        在指定的网卡上，发送tcp 报文到指定的地址
        :param pcap_pointer: 打开网卡的指针 c封装 pcap类型
        :param ip_me: 我方ip unsigned int类型
        :param port_me: 我方端口 unsigned int类型
        :param ip_them: 对方ip unsigned int类型
        :param port_them: 对方端口 unsigned int类型
        :param cookie: seqno 序号 unsigned int类型
        """
        rawsock_send_ipv4(self.px_template, pcap_pointer, ip_me, port_me, ip_them, port_them,
                          cookie)

    def get_port_me(self):
        """
        根据tcp协议，我们需要标识我们自己的发送端口
        :return: int port
        """
        return random.randint(0, self.source_port_range) + self.source_port