# -*- coding:UTF-8 -*-
import struct

from utils import int2ip


class TransParser:
    IP_HEADER_LENGTH = 20  # IP报文头部的长度
    UDP_HEADER_LENGTH = 8  # UDP头部的长度
    TCP_HEADER_LENGTH = 20  # TCP头部的长度


class TCPParser(TransParser):

    @classmethod
    def parser(cls, packet):
        return cls.parse_tcp_header(packet[:cls.TCP_HEADER_LENGTH])


class UDPParser(TransParser):

    @classmethod
    def parse_udp_header(cls, udp_header):
        """
        UDP报文格式
        1. 16位源端口 16位目的端口
        2. 16位UDP长度 16位UDP报文校验和
        :param udp_header:
        :return:
        """
        udp_header = struct.unpack('>HHHH', udp_header)

        # 返回结果
        # src_port 源端口
        # dst_port 目的端口
        # udp_length UDP报文长度
        # udp_checksum UDP报文校验和
        return {

            'src_port': udp_header[0],
            'dst_port': udp_header[1],
            'udp_length': udp_header[2],
            'udp_checksum': udp_header[3]
        }

    @classmethod
    def parser(cls, packet):
        return cls.parse_udp_header(packet[:cls.UDP_HEADER_LENGTH])


def mac_addr_fmt(mac):
    return ["{0:#0{1}x}".format(i, 4) for i in mac]


def parse_icmp(point, px):
    line_len = 4
    icmp_type, icmp_code, icmp_checksum = struct.unpack("!BBH", px[point:point + line_len])
    point += line_len
    rest_of_data = struct.unpack("!I", px[point:point + line_len])
    point += line_len
    point, ip_data = praser_ip_packet(point, px)
    return point, {
        "icmp_type": icmp_type,
        "icmp_code": icmp_code,
        "data": ip_data
    }


def prase_package(px):
    point = 0
    linklayer_len = 14
    dst_mac, src_mac, ether_type = struct.unpack("!6s6sH", px[point:linklayer_len])
    packet = {
        "datalink": {
            "src_mac": src_mac,
            "dst_mac": dst_mac,
        }
    }
    point += linklayer_len
    if ether_type == 0x0800:
        point, ip_data = praser_ip_packet(point, px)
        packet.update(ip_data)
    elif ether_type == 0x0806:
        # prase "arp"
        point, arp_header = prase_arp(point, px)
        packet['arp_header'] = arp_header

    return packet


def praser_ip_packet(point, px):
    """
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        IP报文格式
        1. 4位IP-version 4位IP头长度 8位服务类型 16位报文总长度
        2. 16位标识符 3位标记位 13位片偏移 暂时不关注此行
        3. 8位TTL 8位协议 16位头部校验和
        4. 32位源IP地址
        5. 32位目的IP地址
        """
    line_len = 4
    line1 = struct.unpack("!BBH", px[point:point + line_len])
    # Version, 长度为 4 比特, 表征 IP 协议的版本号, 对 IPv4 来说该字段的值为 4
    version = line1[0] >> 4
    # IHL, 长度为 4 比特, IHL 是 Internet Header Length 的缩写,
    # 以 4 字节为单位指示 IP Header 的长度, 对于 IPv4 来说, Header 的最小长度为 20 字节, 因此该字段的最小值为 5
    ihl = line1[0] & 0b00001111 * 4
    # Type of Service, 服务类型, IETF 在之后将该字段改为 Differentiated Service,
    # 即区分服务, 长度为 8 比特, 该字段用来表达发送端对服务质量的期望程度
    tos = line1[1]
    # Total Length, 长度为 16 比特, 顾名思义该字段以字节为单位指示整个 IP Datagram 的长度
    packet_len = line1[2]
    point += line_len
    line2 = struct.unpack("!HH", px[point:point + line_len])
    # Identification, 长度为 16 比特, 发送方维护一个计数器, 每产生一个 IP Datagram, 计数器的值就加一,
    identification = line2[0]
    # Flags, 长度为 3 比特
    flag = line2[1] & 0b1111000000000000
    # Fragment Offset, 片偏移, 长度为 13 比特
    offset = line2[1] & 0b0000111111111111
    point += line_len
    line3 = struct.unpack("!BBH", px[point:point + line_len])
    # Time to Live, 简称 TTL, 长度为 8 比特
    ttl = line3[0]
    # Protocol, 长度为 8 比特, 用于指示 IP Datagram 携带的数据使用的上层协议类型
    protocol = line3[1]
    # Header Checksum, 长度为 16 比特, 其值为 IP Header 部分的校验和
    header_chm = line3[2]
    point += line_len
    # Source Address, 长度为 32 比特, 源 IP 地址
    # Destination Address, 长度为 32 比特, 目的 IP 地址
    src_ip, dst_ip = struct.unpack("!II", px[point:point + 8])
    point += line_len
    point += line_len
    ip_header = {
        "version": version,
        "ip_header_len": ihl,
        "packet_len": packet_len,
        "identification": identification,
        "flag": flag,
        "TTL": ttl,
        "protocol": protocol,
        "header_chm": header_chm,
        "src_ip": int2ip(src_ip),
        "dst_ip": int2ip(dst_ip)
    }
    if ihl > 20:
        # ip的option选项
        # Padding, 由于 IHL 字段以 4 字节为单位表征 IP Datagram 的 Header 部分的长度,
        # 因此 IP Header 的长度必须是 4 字节的整数倍, 由于 Options 的长度是可变的,
        # 它可能导致整个 IP Header 的长度不是 4 字节的整数倍, 此时需要使用 Padding 字段来填充,
        # Padding 字段的值必须设置为全 0
        point += line_len
    packet = {'ip_header': ip_header}
    if ip_header['protocol'] == 17:
        # udp
        packet['udp'] = UDPParser.parser(px[point:])
    elif ip_header['protocol'] == 6:
        # tcp:
        point, tcp_header = parse_tcp_header(point, px)
        packet['tcp'] = tcp_header
    # elif ip_header['protocol'] == 1:
    #     # icmp :
    #     point, packet['icmp'] = parse_icmp(point, px)
        # point, icmp =  packet['icmp'] = icmp
    return point, packet


def parse_tcp_header(point, px):
    """
    TCP报文格式
    1. 16位源端口号 16位目的端口号
    2. 32位序列号
    3. 32位确认号
    4. 4位数据偏移 6位保留字段 6位TCP标记 16位窗口
    5. 16位校验和 16位紧急指针
    :param tcp_header:
    :return:
    """
    line_len = 4
    src_port, dst_port = struct.unpack('>HH', px[point:point + line_len])
    point += line_len

    line2 = struct.unpack('>L', px[point:point + line_len])
    seq_num = line2[0]
    point += line_len

    line3 = struct.unpack('>L', px[point:point + line_len])
    ack_num = line3[0]
    point += line_len

    line4 = struct.unpack('>BBH', px[point:point + line_len])  # 先按照8位、8位、16位解析
    data_offset = line4[0] >> 4  # 第一个8位右移四位获取高四位
    flags = line4[1] & int(b'00111111', 2)  # 第二个八位与00111111进行与运算获取低六位
    FIN = flags & 1
    SYN = (flags >> 1) & 1
    RST = (flags >> 2) & 1
    PSH = (flags >> 3) & 1
    ACK = (flags >> 4) & 1
    URG = (flags >> 5) & 1
    win_size = line4[2]
    point += line_len

    line5 = struct.unpack('>HH', px[point:point + line_len])
    tcp_checksum = line5[0]
    urg_pointer = line5[1]
    point += line_len
    # 返回结果
    # src_port 源端口
    # dst_port 目的端口
    # seq_num 序列号
    # ack_num 确认号
    # data_offset 数据偏移量
    # flags 标志位
    #     FIN 结束位
    #     SYN 同步位
    #     RST 重启位
    #     PSH 推送位
    #     ACK 确认位
    #     URG 紧急位
    # win_size 窗口大小
    # tcp_checksum TCP校验和
    # urg_pointer 紧急指针
    return point, {
        'src_port': src_port,
        'dst_port': dst_port,
        'seq_num': seq_num,
        'ack_num': ack_num,
        'data_offset': data_offset,
        'flags': {
            'FIN': FIN,
            'SYN': SYN,
            'RST': RST,
            'PSH': PSH,
            'ACK': ACK,
            'URG': URG
        },
        'win_size': win_size,
        'tcp_checksum': tcp_checksum,
        'urg_pointer': urg_pointer
    }


def prase_arp(point, px):
    """
    硬件类型：如以太网（0x0001）、分组无线网。
    协议类型：如网际协议(IP)（0x0800）、IPv6（0x86DD）。
    硬件地址长度：每种硬件地址的字节长度，一般为6（以太网）。
    协议地址长度：每种协议地址的字节长度，一般为4（IPv4）。
    操作码：1为ARP请求，2为ARP应答，3为RARP请求，4为RARP应答。
    源硬件地址：n个字节，n由硬件地址长度得到，一般为发送方MAC地址。
    源协议地址：m个字节，m由协议地址长度得到，一般为发送方IP地址。
    目标硬件地址：n个字节，n由硬件地址长度得到，一般为目标MAC地址。
    目标协议地址：m个字节，m由协议地址长度得到，一般为目标IP地址。
    解析arp报文的
    :param point:
    :param px: 包
    :return:
    """
    hw_address_space, protocol_address_space, hw_len, protocol_len, opcode = struct.unpack("!HHBBH",
                                                                                           px[point:point + 8])
    point += 8

    sender_hw_address, sender_protocol_address = struct.unpack("!6sI", px[point:point + protocol_len + hw_len])
    point += protocol_len + hw_len

    target_hw_address, target_protocol_address = struct.unpack("!6sI", px[point:point + protocol_len + hw_len])
    point += protocol_len + hw_len

    return point, {
        "opcode": opcode,
        "sender_hw_address": mac_addr_fmt(sender_hw_address),
        "sender_protocol_address": sender_protocol_address,
        "target_hw_address": mac_addr_fmt(target_hw_address),
        "target_protocol_address": target_protocol_address
    }


if __name__ == '__main__':
    # mdns
    bad1 = b'\x01\x00^\x00\x00\xfb|\x10\xc9"\xd19\x08\x00E\x00\x008<y\x00\x00\x01\x11\xdb.\xc0\xa8\x00j\xe0\x00\x00\xfb' \
           b'\x14\xe9\x14\xe9\x00$\x1f\x14\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04wpad\x05local\x00\x00\x01' \
           b'\x00\x01 '

    # arp
    bad2 = b'\xff\xff\xff\xff\xff\xffXA \xbd\x85\xc6\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01XA ' \
           b'\xbd\x85\xc6\xc0\xa8\x00\x01\x00\x00\x00\x00\x00\x00\xc0\xa8\x00d '
    prase_package(bad2)

    tcp = b'\xa0x\x17{\x8d\xc6XA \xbd\x85\xc6\x08\x00E\x00\x00(\x94\x9a@\x00,\x06\xf1i\xdc\xb5+\x08\xc0\xa8\x00f\x00P\xd7\xf9\xa7\xe0\xd8\xdc\\\xf8:HP\x10\x03\xb8\xf3\x08\x00\x00'
    print(prase_package(tcp))
    # icmp = 'a078177b8dc62cb21a5cabe00800450000482ab600002c014b73815da403c0a83283030d159e000000004500002c9aa000007d068a9fc0a83283815da403d1c3449300007a300000000060020400eeae000002040218'
    # bits = b''
    # for x in range(0, len(icmp), 2):
    #     # print(icmp[x:x+2])
    #     bits += int(icmp[x:x+2], 16).to_bytes(1, 'big')
    # print(bits)
    icmp = b'\xa0x\x17{\x8d\xc6,\xb2\x1a\\\xab\xe0\x08\x00E\x00\x00H*\xb6\x00\x00,\x01Ks\x81]\xa4\x03\xc0\xa82\x83\x03\r\x15\x9e\x00\x00\x00\x00E\x00\x00,\x9a\xa0\x00\x00}\x06\x8a\x9f\xc0\xa82\x83\x81]\xa4\x03\xd1\xc3D\x93\x00\x00z0\x00\x00\x00\x00`\x02\x04\x00\xee\xae\x00\x00\x02\x04\x02\x18'
    print(prase_package(icmp))
