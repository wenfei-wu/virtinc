#ifndef _NET_H_
#define _NET_H_

#include <stdint.h>
#include <sys/types.h>
#include <stdio.h>
#include <pcap.h>
#include <pthread.h>
#include <time.h>

#define TEST 1

#define INCP_DATA  0
#define INCP_ACK   1

#define SENDER 0
#define SWITCH 1
#define RECEIVER 2
#define UNBLOCK_SWITCH 3

#define PORT_NUM 10
#define SLOT_NUM 100
#define NAME_SIZE 30
#define IP_ADDR_SIZE 30
#define BUFFER_SIZE 1480
#define RECV_LEN 2048
#define INCP_PAYLOAD 128
#define IPC_MSG_SIZE 128

#define MAX_WND_SIZE 10
#define MAX_CONN_NUM 20
#define MAX_DELAY 0.5*CLOCKS_PER_SEC
#define MAX_TASK_NUM 3
#define MAX_SEND_BUF 20

/*******************************************************************************
 * put all data structures and function prototypes here in this file
 ******************************************************************************/

/*******************************************************************************
 * data structures about packet headers, ip_header and layer-4 header
 ******************************************************************************/
typedef struct __attribute__((packed)) IP_Header
{
    uint8_t version:4, headlen:4; // 版本信息(前4位)，头长度(后4位)
    uint8_t type_of_service;      // 服务类型8位
    uint16_t length;              // 整个数据包长度
    uint16_t packet_id;           // 数据包标识
    uint16_t slice_info;          // 分片使用
    uint8_t ttl;                  // 存活时间
    uint8_t type_of_protocol;     // 协议类型
    uint16_t checksum;            // 校验和
    uint32_t src_ip;              // 源ip
    uint32_t dst_ip;              // 目的ip
}ip_header_t; // 总长度5*int32

typedef struct __attribute__((packed)) INCP_Header
{
    uint8_t conn_id;
    uint32_t seq_num;
    uint8_t ack_flag;
    uint16_t payload_length; // payload的长度（ack为0）
    uint16_t offset;
    uint8_t msg_head; // 第一个报文
    uint8_t msg_tail; // 最后一个报文
    uint8_t pad;
}incp_header_t;//总长度4*int32

/*******************************************************************************
 * data structures about packet control, ip_header and layer-4 header
 ******************************************************************************/
typedef struct __attribute__((packed)) incp_packet_control_t in_pcb_t;
struct incp_packet_control_t
{
    incp_header_t incp_head;
    char data[INCP_PAYLOAD+1];
    clock_t time_stamp;
};

typedef struct __attribute__((packed)) ip_packet_control_t ip_pcb_t;
struct ip_packet_control_t
{
    ip_header_t ip_head;
    char data[BUFFER_SIZE];
    ip_pcb_t * next;
};

/*******************************************************************************
 * data structures about packet_info
 ******************************************************************************/
typedef struct _packet_info
{
    uint32_t packet_id;
    uint32_t src_ip;
    uint32_t type;
    uint32_t seq_num;
    uint32_t offset;

    uint32_t length_of_ip;
    uint32_t length_of_incp;
    uint32_t length_of_payload;

    char payload[BUFFER_SIZE];
} packet_info_t;

/*******************************************************************************
 * data structures about sender
 ******************************************************************************/
struct _send_state{
    uint8_t conn_id;
    in_pcb_t ack_window[MAX_WND_SIZE*2];
    int last_sent;
    //int last_acked;
    int ack_until; // 累计最大ack值
    int last_seq_of_current_task; // 当前任务最后一个packet的序号
};

typedef struct _task task_t;
struct _task
{
    int conn_id;
    void* addr; 
    int size;
    int left_size;
    char * src_ip, * dst_ip;
    task_t * next;
};

/*******************************************************************************
 * data structures about receiver
 ******************************************************************************/
struct recv_state{
    uint8_t conn_id;
    int recv_window[MAX_WND_SIZE*2];
    int recv_until; // 按序接收到的最大seq_num
    void *addr; // 接收到的字符串地址
    int size; // recv_bytes长度
    int last_seq_of_current_task; // 当前任务最后一个packet的序号
};

struct arg_t{
    char file_name[NAME_SIZE];
    int conn_id;
    char src_ip[IP_ADDR_SIZE];
    char dst_ip[IP_ADDR_SIZE];
};

typedef struct _ipc_msg ipc_msg_t;
struct _ipc_msg
{
	long msgtype;
	char msgtext[IPC_MSG_SIZE];
};

/*******************************************************************************
 * data structures about rules
 ******************************************************************************/
typedef struct _rule rule_t;
struct _rule
{
    uint32_t src_ip; 
    uint32_t output_port;
    rule_t * next;
};

/*******************************************************************************
 * globals
 ******************************************************************************/
int rank;
pcap_handler grinder;
pcap_t* pcap_handle;
int receive_packet_num;
int send_packet_num;
char * dev_name;
int conn_num;
FILE * fp;
pthread_mutex_t fp_mutex;
pthread_t receive_daemon, sender_process_daemon, receiver_process_daemon;;
pthread_t sender_list[MAX_CONN_NUM];
pthread_t receiver_list[MAX_CONN_NUM];

struct _send_state  send_state;
struct recv_state recv_states[MAX_CONN_NUM];

// 接收缓冲区和发送缓冲区(host)，ip报文格式
ip_pcb_t * receive_buffer_head, * last_receive_buffer;
ip_pcb_t * send_buffer_head, * last_send_buffer;
pthread_mutex_t receive_buffer_mutex;//保护接收缓冲区，接收线程和处理线程都会访问这个buffer
int full_num; // 发送缓冲区当前大小, 最大为MAX_SEND_BUF

// 任务队列(包含一个空的头，从第二个开始才是任务)
task_t *task_queue, *current_task, *last_task;
pthread_mutex_t task_mutex;
pthread_cond_t task_queue_empty;
pthread_cond_t task_queue_full;
int task_num; // 当前任务数, 最大为SLOT_NUM

/*******************************************************************************
 * prototypes
 ******************************************************************************/

//sender、receiver线程相关函数
void init_task_queue();
int init_conn(int conn_id); 
int listen_ipc(int conn_id);
int send_ipc(int conn_id, char * text);
int incp_send(int conn_id, void *addr, unsigned int size, char * src_ip, char * dst_ip); // 构造发送任务，加入队列，监听
int incp_recv(int conn_id, void *addr, unsigned int size); // 构造recv_state，监听

void * run_receiver(void *arg);
void * run_sender(void *arg);

void run_host2(int argc, char** argv);
void run_host1(int argc, char** argv);

//daemon线程相关函数
void set_packet_processor();
uint32_t open_pcap(char * dev_name, pcap_t ** pcap_handle);//返回网卡地址，也就是src_ip
int check(const unsigned char *packet_content);
void encode_incp(in_pcb_t * in_pcb , int seq_num, char * data, int payload_length, int offset);
void encode_ip(ip_pcb_t * ip_pcb, char * src_ip, char * dst_ip, char * data);
void decode_incp_ip(packet_info_t * packet_info, const unsigned char * data);
void print_packet_info(packet_info_t * packet_info);
void decode_and_print(unsigned char *argument, const struct pcap_pkthdr *packet_heaher, const unsigned char *packet_content);

void daemon_end();
void host_end();

void write_receive_buffer(unsigned char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content);
void * run_receive_daemon();

int process_send_window();
void set_task();
void check_timeout();
void make_new_packet();
void send_buffer_packet();
int write_send_buffer(in_pcb_t * current);
void * run_sender_process_daemon();

int reply_ack(in_pcb_t * in_pcb);
int process_receive_window(in_pcb_t * current);
void * run_receiver_process_daemon();

//void run_host(int identity, char * file_name);


/*******************************************************************************
 * states and methods of switches
 ******************************************************************************/

pcap_t* pcap_handle_group[PORT_NUM];

// states about receive time
clock_t time_stamp;

// states about rules
int file_line;
int rules_num;
rule_t * action_list;

// states about ports
int port_num;
char dev_group[PORT_NUM][NAME_SIZE];

// states about threads
int writer_num;

// states about packet buffer
int empty_num;
ip_pcb_t * used_slot_head, *last_used_slot;
ip_pcb_t * unused_slot_head;

// states about locks
pthread_t writer_list[PORT_NUM];
pthread_t writer;// 用于非阻塞switch
pthread_t reader;
pthread_mutex_t slot_mutex;
pthread_mutex_t packet_num_mutex;
pthread_cond_t slot_empty;
pthread_cond_t slot_full;


// method to initialize the switch
int init_switch();
void init_port();
void parse_rulefile(char * file_name);
void parse_rule(rule_t * rule, char * rule_str);
void print_rulelist();
void init_buffer();

// method to run the switch
void run_switch();
void write_buffer(unsigned char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content);
int match_and_send(ip_pcb_t * ip_pcb);//1代表发送成功,-1代表失败
void * run_reader(void *arg);
void * run_writer(void *arg);
void switch_end();
void clean_exit();


//method to run the unblock switch
void run_unblock_switch();
void * run_unblock_receiver();


/*******************************************************************************
 * states and methods of switches
 ******************************************************************************/

#endif
