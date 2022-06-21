#!/bin/env python
# -*- coding:UTF-8 -*-
import argparse

import netifaces
from getmac import get_mac_address

from packet import Packet
from super_scan_c import raw_socket_init, get_adapter_ip
from throttler import Throttler


class PCAP_LINK_TYPE:
    # BSD loopback encapsulation
    LINKTYPE_NULL = 0
    # IEEE 802.3 Ethernet (10Mb, 100Mb, 1000Mb, and up);
    LINKTYPE_ETHERNET = 1
    # Raw IP; the packet begins with an IPv4 or IPv6 header,
    # with the version field of the header indicating whether it's an IPv4 or IPv6 header.
    LINKTYPE_RAW = 101
    # vpn 的类型是12 但是并没有在官网中找到资料，在masscan的源码中找到的
    LINKTYPE_VPN = 12


class Scan_Config:
    def __init__(self, task_queue, max_rate=100, timeout=10):
        """
        初始化网卡配置，通过pcap打开网卡，探测网卡的链路类型，获取网卡ip和arp地址，路由器的ip和arp地址。
        其实在真正发包的时候是不需要路由器的ip地址，只需要arp地址。
        在这里会通过arp协议解析路由器的mac地址，但是非常快，不需要担心会阻塞。
        :param name: 网卡名称
        :param max_rate: 该网卡最大发包量
        :param file_path: 输出文件的位置
        :param ip: 本机ip unsigned int
        :param route: 路由器ip unsigned int
        :param mac_addr: 本机mac地址 类似于这种 [b'\x11', b'\x11', b'\x11' b'\x11' b'\x11' b'\x11']
        :param rt_mac_addr: 路由器mac地址，类似于上面
        """
        gateway = netifaces.gateways()
        # 获取网关的ip地址
        self.route, self.name = gateway['default'][netifaces.AF_INET]
        # 存放pcap的c指针，没有什么情况下不要乱动
        self.pcap = None
        # 网卡链路类型，区分以太网卡，vpn等
        # https://www.tcpdump.org/linktypes.html
        # 默认的话 以太网
        self.link_type = PCAP_LINK_TYPE.LINKTYPE_ETHERNET
        # 网卡初始化，也就是通过pcap打开
        self.pcap = raw_socket_init(self.name)
        # 网卡的ip地址, int类型 不是点分十进制
        self.ip = get_adapter_ip(self.name)
        self.mac_addr = self.strmac2bytemac(get_mac_address(interface=self.name))
        self.rt_mac_addr = self.strmac2bytemac(get_mac_address(ip=self.route))
        # 这个是控制每秒发包的，默认每张网卡100pps 0.1kpps
        # 核心代码逻辑在massscan中
        self.throttler = Throttler(max_rate)
        # 默认ttl 当然也可以修改
        self.TTL = 145
        # 一张网卡就一个seed就行，不需要重复设置
        self.seed = 12345678790
        # 发包的模版，当然，为了省去加锁的烦恼，每个线程一个包模版
        self.packet = Packet(self.mac_addr, self.rt_mac_addr, self.link_type, self.seed)
        self.set_package_ttl(self.TTL)
        # 如果kill为true ，说明已经被关闭线程倒计时超时，需要关闭接收了
        # 该工作由监控进程函数搞定
        self.kill = False
        # 是否已经全部发送完目标
        self.tx_done = False
        # 存放任务列表 只有ip和端口。是一个生成器
        self.task_queue = task_queue
        # 当前网卡发送多少包
        self.packets_sent = 0
        # 有多少任务，为了不阻塞，先设置成-1。在发送进程中再计算。因为计算需要触发生成ip的操作，如果
        # 网段过大，则会导致很长时间
        self.total = -1
        self.timeout = timeout

    def strmac2bytemac(self, strmac):
        """
        aa:bb:cc:dd:ee:ff -> b'\xa0x\x17{\x8d\xc6'
        """
        strmac = strmac.replace(":", "")
        mac = b""
        for i in range(0, 12, 2):
            mac += int(strmac[i:i + 2], 16).to_bytes(1, 'big')
        return mac

    def set_package_ttl(self, ttl):
        self.packet.set_ttl(ttl)

    def get_current_rate(self):
        """
        返回当前扫描的发包速率, 小数点后两位
        :return:
        """
        return self.throttler.get_current_rate()

    def get_task_status(self):
        return round(self.packets_sent / self.total, 2) * 100
