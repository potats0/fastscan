import time


def get_time():
	return int(time.monotonic() * 1000000000 + time.monotonic_ns() / 1000)


def usleep(nanotime):
	time.sleep(nanotime / 1000000.0)
