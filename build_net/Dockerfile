# Base images 基础镜像
FROM ubuntu:20.04

#RUN 执行以下命令 
RUN apt-get update && apt-get install sudo -y && sudo apt-get install vim \
    iproute2 traceroute autoconf make gcc libpcap-dev \
    openssh-server openssh-client ssh -y

#CMD 运行以下命令
CMD tail -f /dev/null