#ifndef _TINY_WEB_H_
#define _TINY_WEB_H_

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <semaphore.h>


#define COMMAN_SIZE 256
#define IP_ADDR_SIZE 32
#define RECV_SIZE 1024
#define NAME_SIZE 32


typedef struct __attribute__((packed)) _web_packet
{
    uint8_t stop_flag;
    uint8_t quit_flag;
    uint8_t msg_flag;
    uint8_t first_flag;
    uint8_t last_flag;
    uint16_t rank;
    uint16_t conn_num;
    uint32_t length; //payload长度
} web_packet_t;



int rank;
int sockfd[3];
int listen_fd;
int conn_num;
pid_t pid;
FILE * fp[3];
struct sockaddr_in docker_addr;
char host_name[3][10] = {"host1", "switch", "host2"};
char ip_str[3][IP_ADDR_SIZE];

#endif