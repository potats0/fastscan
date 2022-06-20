#!/bin/env python
# -*- coding:UTF-8 -*-
import logging
import sys

from scan_config import Scan_Config
from utils import ip2int
import signal

logger = logging.getLogger('flask.app.module')


def transmit_thread(scan_config: Scan_Config):
    ip_me = scan_config.ip
    ip = iter(scan_config.task_queue)
    while scan_config.total - scan_config.packets_sent > 0:
        batch_size = scan_config.throttler.next_batch(scan_config.packets_sent)
        while batch_size >= 0:
            try:
                port_them, ip_them = next(ip)
                port_me = 55555
                ip_them, port_them = ip2int(ip_them), int(port_them)
                cookie = scan_config.packet.syn_cookie(ip_them, port_them, ip_me, port_me)
                scan_config.packet.send_tcp_ipv4(scan_config.pcap, ip_me, port_me, ip_them, port_them, cookie)
                batch_size -= 1
                scan_config.packets_sent += 1
            except StopIteration as e:
                # 这时候任务队列为空，只能退出
                print(e)
                # logger.info("队列无内容，正在准备退出中。。。。")
                break
    logger.info(f"waiting {scan_config.timeout}s")
    signal.alarm(scan_config.timeout)
