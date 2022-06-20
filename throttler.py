# -*- coding:UTF-8 -*-
# 令牌桶算法
import time

import timer


class Throttler:
	class Buckets:
		def __init__(self, timestamp, packet_count):
			self.timestamp = timestamp
			self.packet_count = packet_count
	
	def __init__(self, max_rate):
		self.max_rate = max_rate
		self.buckets_len = 256
		self.buckets = []
		self.index = 0
		for i in range(self.buckets_len):
			timestamp = timer.get_time()
			self.buckets.append(self.Buckets(timestamp, 0))
		self.batch_size = 1
		self.current_rate = 0

	def get_current_rate(self):
		"""
		返回当前运行速度, pps  小数点后两位
		"""
		return round(self.current_rate, 3)
	
	def next_batch(self, packets_sent):
		
		while True:
			timestamp = timer.get_time()
			index = self.index
			self.buckets[index].timestamp = timestamp
			self.buckets[index].packet_count = packets_sent
			
			index = (index + 1)%256
			self.index = index
			old_timestamp = self.buckets[index].timestamp
			old_packet_count = self.buckets[index].packet_count
			
			if timestamp - old_timestamp > 1000000000:
				# throttler_start(throttler, throttler->max_rate);
				self.batch_size = 1
				continue
			
			current_rate = (packets_sent - old_packet_count) / ((timestamp - old_timestamp) / 1000000000)
			
			if current_rate > self.max_rate:
				
				# calculate waittime, in seconds
				waittime = (current_rate - self.max_rate) / self.max_rate
				waittime *= 0.5
				if waittime > 0.1:
					waittime = 0.1
				self.batch_size *= 0.999
				# print("sleep time ", waittime)
				time.sleep(waittime)
				continue
			break
		self.batch_size *= 1.005
		if self.batch_size > 10000:
			self.batch_size = 10000
		self.current_rate = current_rate
		
		return int(self.batch_size)
	