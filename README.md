# virtinc

This project is to emulate a virtual network on a single machine (laptop, server, or workstation). 
In the virtual network, the hosts and switches are Docker containers, and their physical links are veth peers. 

In the host/switch containers, we use libpcap for packet IO. On hosts, we build a user-level network stack;
on switches, we build the the switch logic and the In-Network Computation (INC) logic.

The detailed design is in the Wiki in the Lark documentation.

[Link](https://ad2v5sz0e4.feishu.cn/wiki/wikcnjIWiBEwwJINKjL7sIc8UAc)
