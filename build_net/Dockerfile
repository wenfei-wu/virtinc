# Base images 基础镜像
FROM ubuntu:20.04

#RUN 执行以下命令 
RUN apt-get update && apt-get install sudo -y && sudo apt-get install vim iproute2 traceroute autoconf make uml-utilities -y

#CMD 运行以下命令
CMD mkdir /dev/net -pv && mknod /dev/net/tun c 10 200 \
    && chmod 666 /dev/net/tun && tail -f /dev/null
#CMD tail -f /dev/null

