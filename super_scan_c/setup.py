from distutils.core import setup, Extension
import os

setup(name='SuperScan_C',
      ext_modules=[
          Extension('SuperScan_C',
                    ['stub-pcap.c',
                     'stub-pfring.c',
                     'logger.c',
                     'string_s.c',
                     'rawsock-getif.c',
                     'util-malloc.c',
                     'rawsock.c',
                     'SuperScan.c',
                     'rawsock-getmac.c',
                     'rawsock-getip.c',
                     'rawsock-getroute.c',
                     'stack-arpv4.c',
                     'stack-queue.c',
                     'siphash24.c',
                     'templ-pkt.c',
                     'syn-cookie.c',
                     'templ-payloads.c',
                     'pixie-timer.c',
                     'proto-preprocess.c',
                     'util-checksum.c'],
                    include_dirs=['/opt/homebrew/Frameworks/Python.framework/Headers'],
                    library_dirs=['/usr/local/lib'],
                    )
      ]
      )

# https://mypy.readthedocs.io/en/stable/stubgen.html 记得给c模块加一个pyi文件描述，防止用错
