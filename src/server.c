#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pcap.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <signal.h>

#include "server.h"
#include "util.h"

//打开网卡，返回ip地址
uint32_t open_pcap(char * dev_name, pcap_t ** pcap_handle){
  char errbuf[PCAP_ERRBUF_SIZE];
  uint32_t net_ip;    
  uint32_t net_mask; 
#if TEST
  printf("try to find %s\n", dev_name);
#endif
  int res = pcap_lookupnet(dev_name, &net_ip, &net_mask,  errbuf);
  if(res == -1) {
    printf("pcap_lookupnet(): %s\n", errbuf); 
    clean_exit();
  }

  *pcap_handle = pcap_open_live(dev_name, BUFSIZ, 1, -1, errbuf);
  if(*pcap_handle == NULL) { 
    printf("pcap_open_live(): %s\n", errbuf); 
    clean_exit();
  }
#if TEST
  printf("find %s successfully\n", dev_name);
#endif
  return net_ip;
}

//checksum验证，错误返回0，否则返回1
int check(const unsigned char *packet_content) {
  ip_header_t * ip_head = (ip_header_t *)packet_content;
  int tmpchecksum = ip_head->checksum;
  ip_head->checksum = 0;
  int checksum = compute_checksum(packet_content, ip_head->length);
  ip_head->checksum = tmpchecksum;
  if(checksum != tmpchecksum)
    return 0;
  return 1;
}

// 接收线程接收到数据之后写入缓冲区
void write_receive_buffer(unsigned char *argument, const struct pcap_pkthdr *packet_header,
			  const unsigned char *packet_content){

  printf("func: %s\n", __FUNCTION__);

  // 接收包统计
  receive_packet_num++;
  
  // checksum计算
  if(!check(packet_content)){
    printf("Packet %d: checksum not match\n", receive_packet_num);
    return ;
  }

  // 写入缓冲区
  ip_pcb_t * current = malloc(sizeof(ip_pcb_t));
  memset(current, 0, sizeof(ip_pcb_t));
  memcpy(current, packet_content, packet_header->len);

  printf("receive packet id = %d, FLAG = %d, seq_num = %d, sz = %d\n",
	 ((incp_header_t *)(current->data))->conn_id,
	 ((incp_header_t *)(current->data))->flag,
	 ((incp_header_t *)(current->data))->seq_num,
	 ((incp_header_t *)(current->data))->payload_length);

  int id = ((incp_header_t *)(current->data))->conn_id;
  
  pthread_mutex_lock(&recv_mutex[id]);
  recv_tail[id]->next = current;
  recv_tail[id] = current;
  recv_tail[id]->next = NULL;
  pthread_mutex_unlock(&recv_mutex[id]);
}

// loop接收，调用grinder
void * run_receive_daemon(){
  printf("func: %s\n", __FUNCTION__);
  if(pcap_loop(pcap_handle, -1, write_receive_buffer, NULL) < 0) {
    perror("pcap_loop: ");
  }	
}

void send_packet(ip_pcb_t *ip) {
  int send_bytes = pcap_inject(pcap_handle, ip, ((ip_header_t*)ip)->length);
  if(send_bytes != ((ip_header_t*)ip)->length){
    printf("packet damage: sendbytes = %d length_of_ip = %d\n", 
	   send_bytes, ((ip_header_t*)ip)->length);
    clean_exit();
  }
}

void reply_ack(task_t *task, int seq) {
  ip_pcb_t sd;
  ((ip_header_t *)&sd)->src_ip = task->src;
  ((ip_header_t *)&sd)->dst_ip = task->dst;
  ((incp_header_t *)(sd.data))->conn_id = task->id;
  ((incp_header_t *)(sd.data))->seq_num = seq;
  ((incp_header_t *)(sd.data))->flag = 1;
  ((incp_header_t *)(sd.data))->payload_length = 0;
  ((ip_header_t *)&sd)->length = sizeof(ip_header_t) + sizeof(incp_header_t);
  ((ip_header_t *)&sd)->checksum = 0;
  ((ip_header_t *)&sd)->checksum = compute_checksum(&sd, ((ip_header_t *)&sd)->length);
  send_packet(&sd);
}

void process_packet(task_t *task, ip_pcb_t *packet) {
  int seq = ((incp_header_t *)(packet->data))->seq_num;
  if(seq > task->p + WINDOW_SIZE)
    return ;
  reply_ack(task, seq);
  if(seq < task->p)
    return ;
  int p = seq % WINDOW_SIZE;
  if(task->recv_mask >> p & 1) // repeat
    return ;
  task->recv_mask |= 1 << p;
  memcpy(&(task->packet[p]), packet, sizeof(in_pcb_t));
  for(p = task->p % WINDOW_SIZE; task->recv_mask >> p & 1; p = (p + 1) % WINDOW_SIZE) {
    printf("write: seq = %d, sz = %d\n", task->p, ((incp_header_t *)((task->packet[p]).data))->payload_length);
    fwrite(((in_pcb_t *)((task->packet[p]).data))->data,
	   ((incp_header_t *)((task->packet[p]).data))->payload_length,
	   1, task->fp);
    task->recv_mask ^= 1 << p;
    ++task->p;
  }
  if(task->p == task->packet_num)
    task->state = 2;
}

// 循环阻塞
void* run_receiver(void* conn_id){
  int id = *(int *)conn_id;
  tasks[id].id = id;
  
  printf("func: %s, id: %d\n", __FUNCTION__, id);
  
  char filename[30];
  sprintf(filename, "output_%d.txt", id);
  tasks[id].fp = fopen(filename, "w");

  tasks[id].state = 0;

  ip_pcb_t *cur;
  while(tasks[id].state != 2) {
    cur = recv_head[id]->next;
    if(cur != NULL) {
      if(((incp_header_t *)(cur->data))->flag == 2) { // hakusyu
	printf("link establish!\n");
	tasks[id].state = 1;
	tasks[id].p = 0;
	tasks[id].recv_mask = 0;
	tasks[id].packet_num = ((incp_header_t *)(cur->data))->seq_num;
	tasks[id].dst = ((ip_header_t *)cur)->src_ip;
	tasks[id].src = ((ip_header_t *)cur)->dst_ip;
	((incp_header_t *)(cur->data))->flag = 4;
	((ip_header_t *)cur)->src_ip = tasks[id].src;
	((ip_header_t *)cur)->dst_ip = tasks[id].dst;
	((ip_header_t *)cur)->checksum = 0;
	((ip_header_t *)cur)->checksum = compute_checksum(cur, ((ip_header_t *)cur)->length);
	send_packet(cur);
      }
      else if(((incp_header_t *)(cur->data))->flag == 0) {
	if(tasks[id].state != 1) 
	  printf("link NOT established!\n");
	else 
	  process_packet(&tasks[id], cur);
      }
      else 
	printf("%d: unknown FLAG: %d!\n", id, ((incp_header_t *)(cur->data))->flag);
      pthread_mutex_lock(&recv_mutex[id]);
      recv_head[id]->next = cur->next;
      if(recv_head[id]->next == NULL)
	recv_tail[id] = recv_head[id];
      free(cur);
      pthread_mutex_unlock(&recv_mutex[id]);
    }
  }

  ended_recv |= 1 << id;
  fclose(tasks[id].fp);
}

void clean_exit() {
  if(pcap_handle != NULL)
    pcap_close(pcap_handle);

  ip_pcb_t *prev, *current;
  for(int i = 0; i < conn_num; ++i) {
    pthread_mutex_destroy(&recv_mutex[i]);
    ip_pcb_t* prev = recv_head[i];
    ip_pcb_t* current = prev->next;
    while(current != NULL){
      prev = current;
      current = prev->next;
      free(prev);
    }
    free(recv_head[i]);
  }

  for(int i = 0; i < conn_num; ++i)
    if(tasks[i].state != 2)
      fclose(tasks[i].fp);

  printf("Receiver Exit...\n\n\n");

  exit(0);
}

// host2运行：初始化recv_state, 运行receive线程
int main(int argc, char** argv){
  // 连接数
  conn_num = atoi(argv[2]);
  all_recv = (1 << conn_num) - 1;
  ended_recv = 0;

  // pcap初始化
  dev_name = "host2-iface1";
  open_pcap(dev_name, &pcap_handle);

  // init buffer
  for(int i = 0; i < conn_num; ++i) {
    recv_head[i] = malloc(sizeof(ip_pcb_t));
    memset(recv_head[i], 0, sizeof(ip_pcb_t));
    recv_tail[i] = recv_head[i];
  }

  // init mutex
  for(int i = 0; i < conn_num; ++i)
    pthread_mutex_init(&recv_mutex[i], NULL);

  int res = pthread_create(&receive_daemon, NULL, run_receive_daemon, NULL);
  if(res < 0){
    printf("pthread_create error: %d\n", res);
    clean_exit();
  }

  int conn_group[MAX_CONN_NUM]={};
  for(int i = 0; i < conn_num; ++i){
    // 初始化recv_state
    // 运行receive线程
    conn_group[i] = i;
    int res = pthread_create(&(receiver_list[i]), NULL, run_receiver, &(conn_group[i]));
    if(res < 0){
      printf("pthread_create error: %d\n", res);
      clean_exit();
    }
  }

  while(all_recv != ended_recv) ;

  pthread_kill(receive_daemon, SIGKILL);

  // 回收线程和内存
  for(int i = 0; i < conn_num; ++i){
    pthread_join(receiver_list[i], NULL);
  }
#if TEST
  printf("pthread_join receiver_list finish\n");
#endif
  

  pthread_join(receiver_process_daemon, NULL);
  pthread_join(receive_daemon, NULL);
#if TEST
  printf("pthread_join daemon finish\n");
#endif
  clean_exit();

  return 0;
}

