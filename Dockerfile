FROM ubuntu:20.04

#MAINTAINER danhuang
RUN  sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list

RUN apt-get update -y &&      apt-get install -y python3-pip python3-dev libpcap-dev gcc git unzip

RUN git clone https://github.com/potats0/fastscan.git
WORKDIR fastscan
RUN ls
RUN pip3 install -r requirements.txt
WORKDIR super_scan_c
RUN python3 setup.py build
RUN cp build/lib*/* ./
WORKDIR ..
