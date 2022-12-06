#ifndef _NET_H_
#define _NET_H_

#include <stdint.h>
#include <sys/types.h>
#include <stdio.h>
#include <pcap.h>
#include <pthread.h>

#define TEST 1

#define INCP_DATA  0
#define INCP_ACK   1

#define SENDER 0
#define SWITCH 1
#define RECEIVER 2

#define BUFFER_SIZE 1480
#define SLOT_NUM 50
#define PORT_NUM 10
#define DEV_NAME_SIZE 30
#define IP_ADDR_SIZE 30
#define MAX_WINDOW 20
#define RECV_LEN 2048

/*******************************************************************************
 * put all data structures and function prototypes here in this file
 ******************************************************************************/

/*******************************************************************************
 * data structures about packet headers, ip_header and layer-4 header
 ******************************************************************************/
typedef struct __attribute__((packed)) IP_Header
{
    uint8_t version:4, headlen:4; //版本信息(前4位)，头长度(后4位)
    uint8_t type_of_service; // 服务类型8位
    uint16_t  length; //整个数据包长度
    uint16_t packet_id;  //数据包标识
    uint16_t slice_info; //分片使用
    uint8_t ttl; //存活时间
    uint8_t type_of_protocol; //协议类型
    uint16_t checksum; //校验和
    uint32_t src_ip; //源ip
    uint32_t dst_ip; //目的ip
}ip_header_t;//总长度5*int32

typedef struct __attribute__((packed)) INCP_Header
{
    uint8_t type;
    uint16_t length;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t window_size;

    uint8_t pad[3];
}incp_header_t;//总长度4*int32

/*******************************************************************************
 * data structures about packet control, ip_header and layer-4 header
 ******************************************************************************/
typedef struct incp_packet_control_t in_pcb_t;
struct incp_packet_control_t
{
    incp_header_t incp_head;
    char data[BUFFER_SIZE];
    int isacked;
    in_pcb_t * next;
};


typedef struct ip_packet_control_t ip_pcb_t;
struct ip_packet_control_t
{
    ip_header_t ip_head;
    char data[BUFFER_SIZE];
    ip_pcb_t * next;
};

typedef struct incp_control_block_t
{
    uint32_t window_size;
    uint16_t start;
    uint16_t end;
    uint32_t last_window;
    uint32_t curr_window;
} icb_t;

/*******************************************************************************
 * data structures about packet_info
 ******************************************************************************/
typedef struct _packet_info
{
    uint32_t packet_id;
    uint32_t src_ip;
    uint32_t type;

    uint32_t length_of_ip;
    uint32_t length_of_incp;
    uint32_t length_of_payload;

    char payload[BUFFER_SIZE];
} packet_info_t;

/*******************************************************************************
 * data structures about rules
 ******************************************************************************/
typedef struct _rule rule_t;
struct _rule
{
    uint32_t src_ip; //源ip
    uint32_t output_port;
    rule_t * next;
};

/*******************************************************************************
 * globals
 ******************************************************************************/
int rank;
pcap_handler grinder;
pcap_t* pcap_handle;
//int packet_num;
int receive_packet_num;
int send_packet_num;
char * dev_name;
int seq_num;
icb_t * icb;
FILE * fp;

/*******************************************************************************
 * prototypes
 ******************************************************************************/
void set_packet_processor();
uint32_t open_pcap(char * dev_name);//返回网卡地址，也就是src_ip
void encode_incp(in_pcb_t * in_pcb , int type, int seq_num, int ack_num, char * data);
void encode_ip(ip_pcb_t * ip_pcb, char * src_ip, char * dst_ip, char * data);
void decode_incp_ip(packet_info_t * packet_info, char * data);
void print_packet_info(packet_info_t * packet_info);
void decode_and_print(unsigned char *argument, const struct pcap_pkthdr *packet_heaher, const unsigned char *packet_content);

void * run_receiver(void *arg);
void run_sender(char * file_name, char * src, char * dst);
void run_host(int identity, char * file_name);


/*******************************************************************************
 * states and methods of switches
 ******************************************************************************/

// states about rules
int file_line;
int rules_num;
rule_t * action_list;

// states about ports
int port_num;
char dev_group[PORT_NUM][DEV_NAME_SIZE];

// states about threads
int writer_num;

// states about packet buffer
ip_pcb_t * used_slot_head;
ip_pcb_t * unused_slot_head;

// states about locks
pthread_t writer_list[PORT_NUM];
pthread_t reader;
pthread_mutex_t slot_mutex;
pthread_mutex_t packet_num_mutex;
pthread_cond_t empty;
pthread_cond_t full;
int empty_num;


// method to initialize the switch
int init_switch(int argc, char** argv);
void init_port();
void parse_rulefile(char * file_name);
void parse_rule(rule_t * rule, char * rule_str);
void print_rulelist();
void init_buffer();

// method to run the switch
int run_switch();
void run_writer(unsigned char *argument, const struct pcap_pkthdr *packet_heaher, const unsigned char *packet_content);
int match_and_send(char * data);//1代表发送成功,0代表失败
void * run_reader(void *arg);
void clean_exit();
/*对于sender/receiver，需要关闭什么呢？？
receiver：close(cpap),如果打开了写入的文件需要关掉，有滑动窗口的时候需要把窗口内缓存的释放掉，打印一下接到了多少个包
*/



/*******************************************************************************
 * states and methods of switches
 ******************************************************************************/



#endif
