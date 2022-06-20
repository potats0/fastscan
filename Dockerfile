FROM ubuntu:20.04

#MAINTAINER danhuang
RUN apt-get update & apt-get install python3-pip

RUN pip install -r requirements.txt