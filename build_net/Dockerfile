# Base images 基础镜像
FROM ubuntu:20.04

# RUN timedatectl set-timezone Asia/Shanghai'

RUN apt update && echo -e "6\n70\n" | apt install tzdata \
 && apt-get install sudo -y && sudo apt-get install vim \
    iproute2 traceroute autoconf make gcc libpcap-dev \
    openssh-server openssh-client ssh -y


CMD tail -f /dev/null


