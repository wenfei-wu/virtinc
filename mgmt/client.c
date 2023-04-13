#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/time.h>
#include "tiny_web.h"

// 解析用逗号分隔的三个ip地址
int parse_ip(char * str){
    int ip_len;
    memset(ip_str, 0, sizeof(ip_str));

    char * switch_ip = strchr(str, ',')+1;
    if(switch_ip == NULL)
        return -1;
    
    if((ip_len = switch_ip - str) <= 0)
        return -1;
    memcpy(ip_str[0], str, ip_len);
    ip_str[0][ip_len-1] = '\0';

    char * host2_ip = strchr(switch_ip, ',')+1;
    if(host2_ip == NULL)
        return -1;
    if((ip_len = host2_ip - switch_ip) <= 0)
        return -1;
    memcpy(ip_str[1], switch_ip, ip_len);
    ip_str[1][ip_len-1] = '\0';

    if((ip_len = strlen(host2_ip)) <= 0)
        return -1;
    memcpy(ip_str[2], host2_ip, ip_len);
    ip_str[2][ip_len] = '\0'; 
    return 0;
}

int send_command(int conn_num, int rank){
    // 0是杀死子进程，-1是server退出，>0是conn_num
    // 根据rank建立连接
    web_packet_t packet;
    bzero(&packet, sizeof(web_packet_t));
    if(conn_num == -1){
        packet.quit_flag = 1;
        packet.rank = rank;
        printf("send quit: rank = %d, sockfd(%d)\n", rank, sockfd[rank]);
    }else if(conn_num == 0){
        packet.stop_flag = 1;
        packet.rank = rank;
        printf("send stop: rank = %d, sockfd(%d)\n", rank, sockfd[rank]);
    }else if(conn_num > 0){
        packet.msg_flag = 1;
        packet.rank = rank;
        packet.conn_num = conn_num;
        printf("send conn_num: %d, rank = %d, sockfd(%d)\n", conn_num, rank, sockfd[rank]);
    }else{
        printf("error num: %d\n", conn_num);
        return -1;
    }
    if(send(sockfd[rank], &packet, sizeof(web_packet_t), 0) != sizeof(web_packet_t)){
        perror("send error");
        return -1;
    }
    return 0;   
}

void recv_msg(int rank){
    printf("server recv msg: rank %d\n", rank);
    char buf[RECV_SIZE] = "";
    char file_name[NAME_SIZE]="";
    sprintf(file_name, "%s_output.txt", host_name[rank]);
    fp[rank] = fopen(file_name, "a");

    struct timeval timeout = {3, 0}; 
    setsockopt(sockfd[rank], SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval)); 

    int recv_bytes = recv(sockfd[rank], buf, sizeof(buf), MSG_WAITALL);
    while(recv_bytes > 0){
        buf[recv_bytes] = 0;
        printf("%s", buf);
        fwrite(buf, sizeof(char), strlen(buf), fp[rank]);
        bzero(buf, sizeof(buf));
        recv_bytes = recv(sockfd[rank], buf, sizeof(buf), MSG_WAITALL);
    }   
    fclose(fp[rank]);
}

void recv_reply(int rank){
    printf("recv reply rank: %d\n", rank);

    char buf[RECV_SIZE] = "";
    struct timeval timeout = {3, 0}; 
    setsockopt(sockfd[rank], SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval)); 
    int recv_bytes = recv(sockfd[rank], buf, sizeof(buf), MSG_WAITFORONE);

    if(recv_bytes > 0){
        buf[recv_bytes] = '\0';
        web_packet_t * packet = (web_packet_t *)buf;

        if(packet->quit_flag == 1){
            printf("server quit: rank %d\n", rank);
        }else if(packet->stop_flag == 1){
            printf("server stop: rank %d\n", rank);
        }
    }
    exit(0);
}

void stop(int signo){
    if(rank < 3){
        if(send_command(0, rank) < 0)
            printf("stop error\n");
        recv_msg(rank);
        exit(0);
    }
}


int main(int argc, char * argv[]){
    signal(SIGINT, stop);
    pid_t pid;
    int conn_num;

    // 参数解析
    if(argc < 4 || parse_ip(argv[2]) < 0){
        printf("Form error, please input again\n");
        printf("Right form: run -nodes host1_ip,switch_ip,host2_ip conn_num\n");
    }
    conn_num = atoi(argv[3]);

    for(int i = 0; i < 3; ++i){
        sockfd[i] = socket(AF_INET, SOCK_STREAM, 0);
        bzero(&docker_addr, sizeof(docker_addr));
        docker_addr.sin_family = AF_INET;
        docker_addr.sin_port = htons(8000);
        docker_addr.sin_addr.s_addr = inet_addr(ip_str[i]);
        connect(sockfd[i], (struct sockaddr *)&docker_addr, sizeof(docker_addr));
    }

    while(1){
        for(rank = 0; rank < 3; ++rank){
            pid = fork();
            if(pid == 0){
                //printf("I'm %d child , pid = %u, sockefd = %d\n", rank, getpid(), sockfd[rank]);
                break;
            }
        }

        if(rank < 3){
            if(send_command(conn_num, rank) < 0)
                printf("connect error");
            if(conn_num == -1)
                recv_reply(rank);
            else
                while(1);
        }
        
        while(wait(NULL) > 0);

        if(conn_num == -1)
            return 0;

        char tmp_buf[COMMAN_SIZE]="";
        printf("input: ");
        scanf("%s", tmp_buf);
        if(strcmp(tmp_buf, "quit") == 0){
            conn_num = -1;
        }else{
            conn_num = atoi(tmp_buf);
        }
    }

    return 0;
}