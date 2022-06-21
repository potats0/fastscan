#!/bin/env python
# -*- coding:UTF-8 -*-
import argparse
import faulthandler
import os
import signal
from concurrent.futures import ThreadPoolExecutor

from cidr import cidr
from receive import receive_thread
from scan_config import Scan_Config
from super_scan_c import pcap_init
from transmit import transmit_thread

# 在import之后直接添加以下启用代码即可
faulthandler.enable()

VERSION = 0.01

pcap_init()

executor = ThreadPoolExecutor(5)

running_task = {
    'task_id': '',
}


def start_scan(cidr_list, port, task_id, rate, timeout):
    # 获取默认网卡的名称，也就是能上网的那个网卡的名字
    try:
        ip = cidr(cidr_list, port, task_id)
        scan_config = Scan_Config(ip, rate, timeout)
        running_task['task_id'] = task_id
        running_task['scan_node'] = scan_config
        scan_config.total = scan_config.task_queue.get_tasks_len()

        executor.submit(transmit_thread, scan_config)
        executor.submit(receive_thread, scan_config)

    except Exception as e:
        print(e)


def exit_sign_handler(signal, frame):
    if running_task.setdefault('task_id'):
        if os.path.exists(f"{running_task['task_id']}"):
            os.remove(f"{running_task['task_id']}")
    running_task['scan_node'].kill = True


# register signal.SIGALRM's handler
signal.signal(signal.SIGALRM, exit_sign_handler)

signal.signal(signal.SIGINT, exit_sign_handler)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    # Options
    parser.add_argument('-u', '--url', help='root url', dest='root')
    args = parser.parse_args()
    start_scan(['221.198.70.0/25'], [80], 'aaaa', 100, 10)
