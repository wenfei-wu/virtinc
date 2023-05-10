#ifndef _CLIENT_H_
#define _CLIENT_H_

#include "defs.h"

#define WINDOW_SIZE 16
#define MAX_CONN_NUM 20
#define MAX_DELAY 0.5*CLOCKS_PER_SEC
#define MAX_TASK_NUM 10
#define MAX_SEND_BUF 20

typedef struct {
  int id;
  FILE *fp;
  int src;
  int dst;
  int size;
  int p;
  int packet_num;
  ip_pcb_t packet[WINDOW_SIZE];
  int time[WINDOW_SIZE];
  int ack_mask;
  int state; //{0: close; 1: wait hakusyu; 2: linked}
}task_t;

task_t tasks[MAX_TASK_NUM];

// send message
static char * src_ip = "10.0.0.1";
static char * dst_ip = "10.0.4.1";
static char * file_name = "text.in";

/*******************************************************************************
 * globals
 ******************************************************************************/
int receive_packet_num;
int send_packet_num;
char *dev_name;
int conn_num;

int all_sender, ended_sender;

pthread_t receive_daemon;
pthread_t sender_list[MAX_CONN_NUM];

pcap_t* pcap_handle;

// 接收缓冲区和发送缓冲区(host)，ip报文格式
ip_pcb_t *recv_head[MAX_TASK_NUM], *recv_tail[MAX_TASK_NUM];
pthread_mutex_t recv_mutex[MAX_TASK_NUM]; // for task

void add_to_send(ip_pcb_t *);
void send_packet(ip_pcb_t *);
void process_window(task_t *, int);
void send_tle_packet(task_t *);
void pre_send(task_t *);
void make_and_send(task_t *, int); // IN ORDER!!!!!!!
void init_link(task_t *);

void* run_sender(void *conn_id);

//daemon线程相关函数
uint32_t open_pcap(char * dev_name, pcap_t ** pcap_handle);//返回网卡地址，也就是src_ip
int check(const unsigned char *packet_content);

void write_receive_buffer(unsigned char *argument, const struct pcap_pkthdr *packet_header,
			  const unsigned char *packet_content);

void init_buffer();
void clean_exit();

#endif // _CLIENT_H_
