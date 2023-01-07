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
#include <pthread.h>

#include "net.h"
#include "util.h"

//循环读文件，调用parserule并往action_list里面加节点
void parse_rulefile(char * file_name){
#if TEST
	printf("parse_rulefile\n");
#endif
	fp = fopen(file_name, "r");
	if(fp == NULL){
		perror("parse_rulefile()");
		clean_exit();
	}

	action_list = malloc(sizeof(rule_t));
	if(action_list == NULL){
		perror("parse_rulefile: ");
		clean_exit();
	}
	memset(action_list, 0, sizeof(rule_t));
	rule_t * prev, *current;
	prev = action_list;

	char buf[BUFFER_SIZE+1];
	memset(buf, 0, sizeof(buf));

	while((fgets(buf, BUFFER_SIZE, fp) != NULL)){
		file_line++;
		if(buf[0] == '#' || buf[0] == ';')
			continue;
		rules_num++;

		if(buf[strlen(buf)-1] =='\n')
			buf[strlen(buf)-1] = '\0';

		current = malloc(sizeof(rule_t));
		if(current == NULL){
			perror("parse_rulefile: ");
			clean_exit();
		}
		memset(current, 0, sizeof(rule_t));
		parse_rule(current, buf);
		prev->next = current;
		prev = current;

		memset(buf, 0, sizeof(buf));
	}

	fclose(fp);
}

//解析rule_str，填入rule
void parse_rule(rule_t * rule, char * rule_str){
#if TEST
	printf("parse_rule\n");
#endif
	int num1, num2, num3, num4, output_port;
	char ipaddr[IP_ADDR_SIZE] = {};

	sscanf(rule_str, "Match(%d.%d.%d.%d):Action(%d)", 
			&num1, &num2, &num3, &num4, &output_port);

	sprintf(ipaddr, "%d.%d.%d.%d", num1, num2, num3, num4);

	rule->output_port = output_port;
	rule->src_ip = inet_addr(ipaddr);
	rule->next = NULL;
}

//打印actio_list
void print_rulelist(){
#if TEST
	printf("print_rulelist\n");
#endif
	rule_t * prev, * current;
	prev = action_list;

	while(prev->next != NULL){
		current = prev->next;
		struct in_addr ipaddr;
		memcpy(&ipaddr, &(current->src_ip), 4);
#if TEST		
		printf("Match(%s):Action(%d)\n", inet_ntoa(ipaddr), current->output_port);
#endif
		prev = current;
	}
}

//dev_group初始化
void init_port(){
#if TEST
	printf("init_port\n");
#endif
	for(int i = 0; i < port_num; ++i){
		sprintf(dev_group[i], "switch-iface%d", i+1);
		open_pcap(dev_group[i], &pcap_handle_group[i]);
	}
}

//缓冲区初始化
void init_buffer(){
#if TEST
	printf("init_buffer\n");
#endif
	switch(rank){
		case(SWITCH):
			empty_num = SLOT_NUM;
			used_slot_head = malloc(sizeof(ip_pcb_t));
			unused_slot_head = malloc(sizeof(ip_pcb_t));
			if(used_slot_head == NULL || unused_slot_head == NULL){
				perror("init_buffer: ");
				clean_exit();
			}
			last_used_slot = used_slot_head;
			memset(used_slot_head, 0, sizeof(ip_pcb_t));
			memset(unused_slot_head, 0, sizeof(ip_pcb_t));

#if TEST
	printf("malloc successful\n");
#endif
		
			ip_pcb_t * prev, * current;
			prev = unused_slot_head;
#if TEST
	printf("slot_list init\n");
#endif
			for(int i = 0; i < SLOT_NUM; ++i){
				current = malloc(sizeof(ip_pcb_t));
				if(current == NULL){
					perror("init_buffer: ");
					clean_exit();
				}
				memset(current, 0, sizeof(ip_pcb_t));
				prev->next = current;
				prev = current;
			}
			break;
		case(SENDER):
			full_num = 0;
			send_buffer_head = malloc(sizeof(ip_pcb_t));
			memset(send_buffer_head, 0, sizeof(ip_pcb_t));
			last_send_buffer = send_buffer_head;

			receive_buffer_head = malloc(sizeof(ip_pcb_t));
			memset(receive_buffer_head, 0, sizeof(ip_pcb_t));
			last_receive_buffer = receive_buffer_head;
			break;
		case(RECEIVER):
			full_num = 0;

			receive_buffer_head = malloc(sizeof(ip_pcb_t));
			memset(receive_buffer_head, 0, sizeof(ip_pcb_t));
			last_receive_buffer = receive_buffer_head;
			break;
		default:
			printf("error rank: %d\n", rank);
			break;
	}
}

int init_switch(){
	// 初始化规则列表
	parse_rulefile("src/switch.config");

	// 初始化端口
	port_num = 2;
	init_port();

	// 初始化包处理函数
	set_packet_processor();

	// 初始化缓冲区
	init_buffer();

	// 初始化线程
	writer_num = port_num;

	// 初始化锁
	pthread_mutex_init(&packet_num_mutex, NULL);
	pthread_mutex_init(&slot_mutex, NULL);
	pthread_cond_init(&slot_empty, NULL);
	pthread_cond_init(&slot_full, NULL);
	return 0;
}

//checksum检查，获得锁然后写入缓冲区（链表操作），释放锁
void write_buffer(unsigned char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content){
#if TEST
	printf("run_writer\n");
#endif
	pthread_mutex_lock(&packet_num_mutex);
	receive_packet_num++;
	
	time_stamp = clock();

#if TEST
	printf("receive packet num: %d\n", receive_packet_num);
#else
	if(receive_packet_num % 50 == 0)
		printf("receive_packet_num = %d\n", receive_packet_num);
#endif
	pthread_mutex_unlock(&packet_num_mutex);

	//checksum检查
	if(!check(packet_content)){
		printf("Packet %d: checksum not match\n", receive_packet_num);
	}


	//消费者操作
	pthread_mutex_lock(&slot_mutex);
	while(empty_num == 0){
		pthread_cond_wait(&slot_empty, &slot_mutex);
	}

	//写入缓冲区（链表操作）
	ip_pcb_t * current = unused_slot_head->next;
	unused_slot_head->next = current->next;
	memcpy(current, packet_content, packet_header->len);
	// 插入used_slot队列最后
	last_used_slot->next = current;
	last_used_slot = current;
	last_used_slot->next = NULL;
	empty_num--;

	pthread_cond_signal(&slot_full);
	pthread_mutex_unlock(&slot_mutex);

	return;
}

int match_and_send(ip_pcb_t * ip_pcb){
#if TEST
	printf("match_and_send\n");
#endif
	ip_header_t * ip_head = (ip_header_t *)ip_pcb;

	rule_t * prev_rule = action_list;
	rule_t *curr_rule = prev_rule->next;
	while(curr_rule != NULL){
		if(curr_rule->src_ip == ip_head->src_ip){
			int send_bytes = pcap_inject(pcap_handle_group[curr_rule->output_port-1], ip_pcb, ip_head->length);
			if(send_bytes != ip_head->length){
				perror("packet damage: ");
        	}
		send_packet_num++;
	
#if TEST
	incp_header_t * incp_head = (incp_header_t *)(ip_pcb->data);
	struct in_addr addr;
	memcpy(&addr, &(ip_head->dst_ip), 4);
	printf("send packet %d to %s: seq_num = %d\n", send_packet_num, inet_ntoa(addr), incp_head->seq_num);
#else
	if(send_packet_num % 50 == 0)
		printf("send_packet_num = %d\n", send_packet_num);

#endif
			return 1;
		}
		prev_rule = curr_rule;
		curr_rule = prev_rule->next;
	}
	return -1;
}

//获得锁，遍历，读出，调整链表,释放锁
void * run_reader(void *arg){
#if TEST
	printf("run_reader\n");
#endif
	while(1){
#if TEST
	printf("\nI'm reader\n");
#endif		
		//生产者操作
		pthread_mutex_lock(&slot_mutex);
		while(empty_num == SLOT_NUM){
			pthread_cond_wait(&slot_full, &slot_mutex);
		}

		//遍历，读出，调整链表
		ip_pcb_t * current = used_slot_head->next;
		if(current != NULL)
		{
			used_slot_head->next = current->next;
			if(used_slot_head->next == NULL){
				last_used_slot = used_slot_head;
			}
			pthread_mutex_unlock(&slot_mutex);
			int res = match_and_send(current);
			if(res < 0){
				printf("error packet: cannot found port to send: ");
			
				struct in_addr addr;
				memcpy(&addr, &(((ip_header_t*)current)->src_ip), sizeof(uint32_t));
				printf("src_ip = %s\n", inet_ntoa(addr));
			}
			memset(current, 0, sizeof(ip_pcb_t));
			pthread_mutex_lock(&slot_mutex);
			empty_num++;

			current->next = unused_slot_head->next;
			unused_slot_head->next = current;
		}
		else
		{
			printf("slot error: empty_num = %d current == NULL\n", empty_num);
		}

		pthread_cond_signal(&slot_empty);
		pthread_mutex_unlock(&slot_mutex);
	}
	
}

//switch设置包处理器，开始收包
void * run_writer(void *arg){
	int idx = *((int*)arg);
	if(pcap_loop(pcap_handle_group[idx], -1, grinder, NULL) < 0)
	{
		perror("pcap_loop: ");
	}	
}

//三种终端的资源回收退出程序
void clean_exit(){
	switch (rank)
	{
	case RECEIVER:
		{
			if(pcap_handle != NULL)
				pcap_close(pcap_handle);
			if(fp != NULL)
				fclose(fp);

			for(int i = 0; i < conn_num; ++i){
				free(recv_states[i].addr);
			}

			//buffer
			pthread_mutex_destroy(&receive_buffer_mutex);
			ip_pcb_t* prev = receive_buffer_head;
			ip_pcb_t* current = prev->next;
			while(current != NULL){
				prev = current;
				current = prev->next;
				free(prev);
			}
			free(receive_buffer_head);

			printf("total received packet: %d\n", receive_packet_num);
			printf("Receiver Exit...\n\n\n");

			exit(0);
		}
		break;
	case SENDER:
		{
			if(pcap_handle != NULL)
				pcap_close(pcap_handle);
			if(fp != NULL)
				fclose(fp);
			
			//task_queue
			task_t * prev_task = task_queue;
			task_t * curr_task = task_queue->next;
			while (curr_task != NULL)
			{
				prev_task = curr_task;
				curr_task = prev_task->next;
				free(prev_task);
			}
			free(task_queue);

			//buffer
			ip_pcb_t* prev = receive_buffer_head;
			ip_pcb_t* current = prev->next;
			while(current != NULL){
				prev = current;
				current = prev->next;
				free(prev);
			}
			free(receive_buffer_head);

			prev = send_buffer_head;
			current = prev->next;
			while(current != NULL){
				prev = current;
				current = prev->next;
				free(prev);
			}
			free(send_buffer_head);

			// 锁
			pthread_mutex_destroy(&fp_mutex);
			pthread_mutex_destroy(&receive_buffer_mutex);
			pthread_mutex_destroy(&task_mutex);
			pthread_cond_destroy(&task_queue_empty);
			pthread_cond_destroy(&task_queue_full);
			
			printf("total sended packet: %d\n", send_packet_num);
			printf("Sender Exit...\n\n\n");

			exit(0);
		}
		break;
	case SWITCH:
		{for(int i = 0; i <= writer_num; ++i){
			if(pcap_handle_group[i] != NULL)
				pcap_close(pcap_handle_group[i]);
		}

		// actionlist
		rule_t * prev_rule = action_list;
		rule_t * curr_rule = prev_rule->next;
		while(curr_rule != NULL){
			prev_rule->next = curr_rule->next;
			free(curr_rule);
			curr_rule = prev_rule->next;
		}
		free(action_list);

		//缓冲区
		ip_pcb_t* prev = used_slot_head;
		ip_pcb_t* current = prev->next;
		while(current != NULL){
			prev->next = current->next;
			free(current);
			current = prev->next;
		}
		free(used_slot_head);

		prev = unused_slot_head;
		current = prev->next;
		while(current != NULL){
			prev->next = current->next;
			free(current);
			current = prev->next;
		}
		free(unused_slot_head);
	
		//锁
		pthread_mutex_destroy(&packet_num_mutex);
		pthread_mutex_destroy(&slot_mutex);
   		pthread_cond_destroy(&slot_empty);
		pthread_cond_destroy(&slot_full);

		printf("Switch Exit...\n\n\n");
		exit(0);}
		break;
	case UNBLOCK_SWITCH:
		{printf("error rank: unblock switch\n");
		printf("Exit...\n");
		exit(0);}
		break;
	default:
		{printf("error rank: %d\n", rank);
		printf("Exit...\n");
		exit(0);}
		break;
	}
}

void run_switch(){
#if TEST
	printf("\nrun_switch\n");
	printf("create writers\n");
#endif
	signal(SIGTERM, host_end);
	signal(SIGALRM, daemon_end);
	
	int port_group[writer_num];
	for(int i = 0; i < writer_num; ++i){
		port_group[i] = i;
		int res = pthread_create(&(writer_list[i]), NULL, run_writer, &(port_group[i]));
		if(res < 0){
			printf("pthread_create error: %d\n", res);
			clean_exit();
		}
	}
	
#if TEST
	printf("create reader\n");
#endif

	int res = pthread_create(&reader, NULL, run_reader, NULL);
	if(res < 0){
		printf("pthread_create error: %d\n", res);
		clean_exit();
	}


	for(int i = 0; i < writer_num; ++i){
		pthread_join(writer_list[i], NULL);
#if TEST
		printf("pthread_join: writer %d\n", i);
#endif
	}
	pthread_join(reader, NULL);
#if TEST	
	printf("pthread_join: reader\n");
#endif	
	clean_exit();
	
	return;
}

//使用dispatch循环接收包的switch
void run_unblock_switch(){
#if TEST
	printf("\nrun_unblock_switch\n");
	printf("create writer\n");
#endif

	int res = pthread_create(&writer, NULL, run_unblock_receiver, NULL);
	if(res < 0){
			printf("pthread_create error: %d\n", res);
			clean_exit();
	}
#if TEST
	printf("create reader\n");
#endif

	res = pthread_create(&reader, NULL, run_reader, NULL);
	if(res < 0){
		printf("pthread_create error: %d\n", res);
		clean_exit();
	}


	pthread_join(writer, NULL);
#if TEST	
	printf("pthread_join: writer\n");
#endif


	pthread_join(reader, NULL);
#if TEST	
	printf("pthread_join: reader\n");
#endif
	return;
}

//一个线程循环接收各个端口上的包
void * run_unblock_receiver(){
	//循环逻辑，调用run_writer
#if TEST
    printf("run_unblock_receiver\n");
#endif
	set_packet_processor();
	char errbuf[BUFFER_SIZE];

#if TEST
    printf("open_pcap\n");
#endif
	//打开所有端口
	for(int i = 0; i < port_num; ++i){
		open_pcap(dev_group[i], &(pcap_handle_group[i]));
		pcap_setnonblock(pcap_handle_group[i], 1, errbuf);
	}

	//循环接收包
	while(1){
		for(int i = 0; i < port_num; ++i){
			if(i == 1)//略过端口2
				continue;
			if(pcap_dispatch(pcap_handle_group[i], -1, grinder, NULL) < 0)
			{
				perror("pcap_dispatc: ");
			}
		}
	}

	//关闭
	for(int i = 0; i < port_num; ++i){
		pcap_close(pcap_handle_group[i]);
	}
}