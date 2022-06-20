# -*- coding:UTF-8 -*-
"""
该文件专门用来处理ip地址，包括将ip地址存放到文件中，随机化ip地址等算法
"""
import ipaddress
import logging
import os
import random
import tempfile

from utils import ip2int, int2ip

logger = logging.getLogger('flask.app.module')

MAGIC_NUMBER = b't66y'
# 因为需要写入magnic，所以读取的内容都需要从magic往后读
FILE_START_POS = len(MAGIC_NUMBER)


class cidr:
    """
    在扫描ipv4网段时候，存储ipv4地址空间是个大问题。尤其在小内存vps上 很容易OOM，所以使用文件代替内存
    """

    def __init__(self, cidr_list: list, ports: list, file=None):
        """
        初始化，包括创建临时文件
        :param cidr_list: 存放cidr网段的list ['192.168.1.0/24', '192.168.2.0/24']
        :param ports: 存放端口
        :param file: 如果提供file参数，那么说明从该文件中生成
        """
        if file:
            self.path = file
        else:
            self.fd, self.path = tempfile.mkstemp()
        logger.debug(f"临时存放文件名 {self.path}")
        # 如果用户提供的文件真的存在，我们才打开，否则就新建
        if os.path.exists(self.path):
            self.file = open(self.path, 'rb+')
        else:
            self.file = open(self.path, 'wb+')
        self.cidr_list = cidr_list
        # 当前文件指针, 为了生成器准备
        self.current_pointer = 0
        # 当前存储了多少ip地址
        self.ips_len = 0
        self.ports = ports
        # 如果生成完ip地址，那么为true，方便监控
        self.finished = False

    def generate_ips(self):
        """
        根据input中的cidr网段，生成所有ip地址
        """
        count = 0
        """
        存放ip地址的文件的数据结构, 开头四个字节是本文件ip地址的数量，大端
        每个ip地址按照四字节存储，无分隔符
        """
        magic = self.file.read(4)
        if magic == MAGIC_NUMBER:
            # 说明已经搞定了，只需要重新读取文件里的内容就行
            count = self.file.read(4)
            self.ips_len = int.from_bytes(count, "big")
            self.finished = True
        else:
            # 重新生成ip地址
            self.file.write(MAGIC_NUMBER)
            self.file.write(int(0).to_bytes(4, byteorder="big"))
            for ip in self.cidr_list:
                try:
                    net = ipaddress.ip_network(ip)
                    for i in net:
                        self.file.write(ip2int(i).to_bytes(4, byteorder="big"))
                        count += 1
                except ValueError as e:
                    print(e)
            self.file.seek(FILE_START_POS)
            # 写入ip地址数量
            self.file.write(count.to_bytes(4, byteorder="big"))
            self.ips_len = count
            self.shuffle_ips()
            self.finished = True

    def shuffle_ips(self):
        """
        将input_file中的ip地址做随机化处理
        """
        for i in range(self.ips_len):
            # 取出原本位置的ip地址 +4 的原因是需要考虑写入的ip地址数
            self.file.seek(i * 4 + 4 + FILE_START_POS)
            ip = self.file.read(4)

            # 随机位置
            random_index = random.randint(0, self.ips_len - 1)
            self.file.seek(random_index * 4 + 4 + FILE_START_POS)
            ip2 = self.file.read(4)
            # 读取完ip后，文件指针需要再后退到刚才的位置，
            self.file.seek(random_index * 4 + 4 + FILE_START_POS)
            self.file.write(ip)

            self.file.seek(i * 4 + 4 + FILE_START_POS)
            self.file.write(ip2)

    def get_tasks_len(self):
        if self.ips_len == 0:
            # 说明还没有动态生成，需要先动态生成
            self.generate_ips()
        return self.ips_len * len(self.ports)

    def __iter__(self):
        if self.ips_len == 0:
            # 说明还没有动态生成，需要先动态生成
            self.generate_ips()
        for port in self.ports:
            self.file.seek(0)
            self.current_pointer = 0
            while True:
                if self.current_pointer < self.ips_len:
                    self.file.seek(self.current_pointer * 4 + 4 + FILE_START_POS)
                    ip = self.file.read(4)
                    ip = int2ip(int.from_bytes(ip, 'big'))
                    self.current_pointer += 1
                    yield port, ip
                else:
                    break

    def close(self):
        """
        删除临时文件资源
        """
        os.remove(self.path)

    def __enter__(self):
        return self

    def __exit__(self, type, value, trace):
        self.close()


if __name__ == '__main__':

    # with open("target", 'r') as f:
    ip_list = ['192.168.1.0/24']
    ips = cidr(ip_list, [80, 443], 'project1')
    print(ips.get_tasks_len())
    ip = iter(ips)
    while True:
        try:
            print(next(ip))
        except StopIteration:
            break
