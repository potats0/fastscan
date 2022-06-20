from typing import Any, NoReturn

from scan_config import Scan_Config


def arp_resolv(adapter: Scan_Config, ip_me: int, ip_them: int, my_mac: bytes) -> Any: ...

"""
在指定的网卡上，向指定的ip发送arp请求对方的mac地址
"""


def get_adapter_ip(ifname: str) -> int: ...


"""
获取网卡的ip地址
"""


def get_adapter_mac(ifname: str) -> bytes: ...


"""
获取网卡的mac地址
"""


def get_default_gateway(ifname: str) -> int: ...


"""
根据网卡名称获取默认网关
"""


def get_default_nic() -> str: ...


"""
获取系统默认网卡
"""


def pcap_init() -> NoReturn: ...


"""
初始化pcap运行环境，也就是动态链接。一般在linux中，pcap库默认存在
"""


def raw_socket_init(adapter: Scan_Config, ifname: str) -> NoReturn: ...


"""
网卡初始化，设置pcap的发包环境
"""


def rawsock_recv_packet(pcap) -> bytes: ...

"""
关闭pcap
"""


def pcap_close(pcap) -> NoReturn: ...



"""
从网卡直接接收数据，包含二层以太网帧，如果出错，那么返回none
"""


def rawsock_send_ipv4(px_template_py, pcap_py, ip_me, port_me, ip_them, port_them, seqno) -> NoReturn: ...


"""
发送ipv4报文，包含以太网帧，同步过程，无法异步。具体发送速率由网卡决定，也就是CSMA/CD
"""


def siphash24(ip_me: int, port_me: int, ip_them: int, port_them: int, entropy: int) -> int: ...


"""
siphash24计算
"""


def template_packet_init(*args, **kwargs) -> Any: ...


def template_set_ttl(*args, **kwargs) -> Any: ...
