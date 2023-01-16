#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#include "tiny_web.h"


/*
*  运行在docker的服务器
*/
int main(){
    int listen_fd;
    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in my_addr;
	bzero(&my_addr,sizeof(my_addr));

	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(8000);
	my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	bind(listen_fd, (struct sockaddr *)&my_addr, sizeof(my_addr));

    listen(listen_fd, 10);
    struct sockaddr_in cli_addr;
	socklen_t cli_len = sizeof(cli_addr);
	int conn_fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
    char buf[COMMAN_SIZE]="";

    while(recv(conn_fd, buf, sizeof(web_packet_t), 0) > 0){
        web_packet_t * packet = (web_packet_t *)buf;
    
        if(packet->msg_flag == 1){
            printf("recv msg: rank = %d\n", packet->rank);
            rank = packet->rank;
            conn_num = packet->conn_num;
            if((pid = fork()) == 0){
                // 执行
                printf("conn_num = %d\n", packet->conn_num);
                char rank_str[NAME_SIZE]=""; 
                sprintf(rank_str, "%d", rank);
                char conn_num_str[NAME_SIZE]=""; 
                sprintf(conn_num_str, "%d", conn_num);
                char * argv[] = {"../bin/main.o", rank_str, conn_num_str};
                char * envp[] = {NULL};
                dup2(conn_fd, STDOUT_FILENO);
                execve("../bin/main.o", argv, envp);
              
            }
        }else if(packet->stop_flag == 1){
            printf("recv stop: rank = %d\n", packet->rank);
            kill(pid, SIGTERM);
            wait(NULL);
            send(conn_fd, buf, sizeof(web_packet_t), 0);
            printf("stop\n");
        }else if(packet->quit_flag == 1){
            kill(pid, SIGTERM);
            wait(NULL);
            printf("recv quit: rank = %d\n", packet->rank);
            send(conn_fd, buf, sizeof(web_packet_t), 0);
            printf("quit\n");
            break;
        }
        memset(buf, 0, sizeof(buf));
    }
    close(conn_fd);
    close(listen_fd);
    return 0;
}   