#ifndef _SWITCH_H_
#define _SWITCH_H_

#include "defs.h"

#define PORT_NUM 10
#define NAME_SIZE 30
#define SLOT_NUM 100

#define MAX_DELAY (0.5 * CLOCKS_PER_SEC)

int send_packet_num;
int receive_packet_num;

pthread_t p_tle_resend;
pthread_t writer_list[PORT_NUM];
pthread_t writer;// 用于非阻塞switch
pthread_t reader;
pthread_cond_t slot_empty;
pthread_cond_t slot_full;
pthread_mutex_t slot_mutex;
pthread_mutex_t packet_num_mutex;

int empty_num;
ip_pcb_t * used_slot_head, *last_used_slot;
ip_pcb_t * unused_slot_head;

// states about threads
int writer_num;

// states about receive time
clock_t time_stamp;

pcap_t* pcap_handle_group[PORT_NUM];

static const char *init_sw_link_format;

#define KEY_BASE 8
#define KEY_LENGTH 52
#define KEY_SIZE KEY_LENGTH

// for calc
static uint8_t key_key[KEY_LENGTH];
static uint8_t key_g[KEY_LENGTH];
static uint8_t key_p[KEY_LENGTH];
static uint8_t key_a[KEY_LENGTH];

#define WINDOW_SIZE 16

static uint32_t total_packets;

// switch/calc buffer
static ip_pcb_t agg_buffer[WINDOW_SIZE];
static uint32_t agg_p;
static uint8_t agg_flag[WINDOW_SIZE];
static uint32_t agg_time[WINDOW_SIZE];
static uint32_t agg_port[WINDOW_SIZE];

// states about ports
int port_num;
char dev_group[PORT_NUM][NAME_SIZE];

pcap_t* pcap_handle;

// actions
int action_nop(ip_pcb_t *, int);
int action_clear(ip_pcb_t *, int); // clear payload
int action_aggregation_src(ip_pcb_t *, int); // from source
int action_sw_ack(ip_pcb_t *, int); // ack
int action_aggregation_calc(ip_pcb_t *, int); // from calc
int action_calc_ack(ip_pcb_t *, int); // g^b -> key
int action_load_a(ip_pcb_t *, int); // load p, g, g^a
int action_load_b(ip_pcb_t *, int); // load g^b
int action_save_a(ip_pcb_t *, int);
int action_generate_key(ip_pcb_t *, int);
int action_save_total(ip_pcb_t *, int);
static int (*action_list[20])(ip_pcb_t *, int) =
  {action_nop, action_clear,
   action_aggregation_src, action_sw_ack,
   action_aggregation_calc, action_calc_ack,
   action_load_a, action_load_b,
   action_save_a, action_generate_key,
   action_save_total};	

// send packet {1} to port {2}
void sw_send(ip_pcb_t *, int);

// resend timeout packet 
void *tle_send(void *);

// method to initialize the switch
int init_switch();
void init_port();
void init_buffer();

// method to run the switch
void run_switch();
void write_buffer(unsigned char *argument, const struct pcap_pkthdr *packet_header,
		  const unsigned char *packet_content);
int match_and_send(ip_pcb_t * ip_pcb);//1代表发送成功,-1代表失败
void *run_reader(void *arg);
void *run_receiver(void *arg);

void clean_exit();

void host_end();
void daemon_end();

int check(const unsigned char *);

uint32_t open_pcap(char *, pcap_t **);

#endif // _SWITCH_H_
