FROM ubuntu:20.04

#MAINTAINER danhuang
RUN  sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list

RUN apt-get update -y &&      apt-get install -y python3-pip python3-dev libpcap-dev gcc git unzip

RUN git clone https://github.com/potats0/fastscan.git && cd fastscan && pip3 install -r requirements