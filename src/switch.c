#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
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
	}
}

//缓冲区初始化
void init_buffer(){
#if TEST
	printf("init_buffer\n");
#endif
	empty_num = SLOT_NUM;

	used_slot_head = malloc(sizeof(ip_pcb_t));
	unused_slot_head = malloc(sizeof(ip_pcb_t));
	if(used_slot_head == NULL || unused_slot_head == NULL){
		perror("init_buffer: ");
		clean_exit();
	}

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
}

int init_switch(int argc, char** argv){
	rank = SWITCH;

	//初始化规则列表
	if(argc >= 4)
		parse_rulefile(argv[3]);
	else
		parse_rulefile("src/switch.config");

	//初始化端口
	port_num = atoi(argv[2]);
	init_port();

	//初始化缓冲区
	init_buffer();

	//初始化线程
	writer_num = port_num;

	//初始化锁
	pthread_mutex_init(&packet_num_mutex, NULL);
	pthread_mutex_init(&slot_mutex, NULL);
	pthread_cond_init(&empty, NULL);
	pthread_cond_init(&full, NULL);
	return 0;
}

//checksum检查，获得锁然后写入缓冲区（链表操作），释放锁
void run_writer(unsigned char *argument, const struct pcap_pkthdr *packet_heaher, const unsigned char *packet_content){

#if TEST
	printf("run_writer\n");
#endif

	//从端口2发出去的包不能收
	if(strcmp(argument, "10.0.1.0") == 0){
		return;
	}

	pthread_mutex_lock(&packet_num_mutex);
#if TEST
	printf("receive packet num: %d\n", receive_packet_num);
#else
	if(receive_packet_num % 10 == 0)
		printf("receive_packet_num == %d\n", receive_packet_num);
#endif
	pthread_mutex_unlock(&packet_num_mutex);

	//checksum检查
    ip_header_t * ip_head = (ip_header_t *)packet_content;

	char buf[BUFFER_SIZE]={};
    memcpy(buf, packet_content, ip_head->length);
    ip_head = (ip_header_t *)buf;

    uint16_t tmp_checksum = ip_head->checksum;
    ip_head->checksum = 0;
    if(tmp_checksum != compute_checksum(buf, ip_head->length)){
        printf("packet %d: checksum not match\n", receive_packet_num);
		return;
    }

	ip_head->checksum = tmp_checksum;

	packet_info_t * packet_info = malloc(sizeof(packet_info_t));
	if(packet_info == NULL){
		perror("run_swriter: ");
		clean_exit();
	}
	memset(packet_info, 0, sizeof(packet_info_t));
	pthread_mutex_lock(&packet_num_mutex);
	packet_info->packet_id = receive_packet_num;
	pthread_mutex_unlock(&packet_num_mutex);

	decode_incp_ip(packet_info, buf);

#if TEST
	print_packet_info(packet_info);
#endif

	free(packet_info);


	//消费者操作
	pthread_mutex_lock(&slot_mutex);
	while(empty_num == 0){
		pthread_cond_wait(&empty, &slot_mutex);
	}

	//写入缓冲区（链表操作）tbc
	ip_pcb_t * current = unused_slot_head->next;
	memcpy(current, buf, ip_head->length);
	unused_slot_head->next = current->next;
	current->next = used_slot_head->next;
	used_slot_head->next = current;

	empty_num--;
	pthread_cond_signal(&full);
	pthread_mutex_unlock(&slot_mutex);

	return;
}

int match_and_send(char * data){
#if TEST
	printf("match_and_send\n");
#endif

	packet_info_t * packet_info = malloc(sizeof(packet_info_t));
	if(packet_info == NULL){
		perror("match_and_send: ");
		clean_exit();
	}
	memset(packet_info, 0, sizeof(packet_info_t));


	packet_info->packet_id = send_packet_num;
	decode_incp_ip(packet_info, data);

	rule_t * prev_rule = action_list;
	rule_t *curr_rule = prev_rule->next;
	while(curr_rule != NULL){
		if(curr_rule->src_ip == packet_info->src_ip){
			open_pcap(dev_group[curr_rule->output_port-1], &(pcap_handle_group[port_num]));


			int send_bytes = pcap_inject(pcap_handle_group[port_num], data, packet_info->length_of_ip);
			if(send_bytes != packet_info->length_of_ip){
				perror("packet damage: ");
        	}
		send_packet_num++;
		
#if TEST
	printf("send packet %d successesfully\n\n", send_packet_num);
#else
	if(send_packet_num % 10 == 0)
			printf("send_packet_num = %d\n", send_packet_num);
#endif
			
			free(packet_info);
			if(pcap_handle_group[port_num] != NULL)
				pcap_close(pcap_handle_group[port_num]);


			return 1;
		}
		prev_rule = curr_rule;
		curr_rule = prev_rule->next;
	}
	free(packet_info);
	return -1;
}

//获得锁，遍历，读出，调整链表,释放锁
void * run_reader(void *arg){
#if TEST
	printf("run_reader\n");
#endif
	while(1){
#if TEST
	printf("I'm reader\n");
#endif		
		//生产者操作
		pthread_mutex_lock(&slot_mutex);
		while(empty_num == SLOT_NUM){
			pthread_cond_wait(&full, &slot_mutex);
		}

		//遍历，读出，调整链表tbc
		ip_pcb_t * current = used_slot_head->next;
		if(current != NULL)
		{
			used_slot_head->next = current->next;
			pthread_mutex_unlock(&slot_mutex);
			int res = match_and_send((char*)current);
			if(res < 0){
				printf("error packet: cannot found port to send\n");
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

		pthread_cond_signal(&empty);
		pthread_mutex_unlock(&slot_mutex);
	}
	
}

//三种终端的资源回收退出程序
void clean_exit(){
	switch (rank)
	{
	case RECEIVER:
		if(pcap_handle != NULL)
			pcap_close(pcap_handle);
		if(fp != NULL)
			fclose(fp);

		printf("total received packet: %d\n", receive_packet_num);
		printf("Receiver Exit...\n");

		exit(0);
		break;
	case SENDER:
		if(pcap_handle != NULL)
			pcap_close(pcap_handle);
		if(fp != NULL)
			fclose(fp);

		printf("total sended packet: %d\n", send_packet_num);
		printf("Sender Exit...\n");

		exit(0);
		break;
	case SWITCH:
		for(int i = 0; i <= writer_num; ++i){
			if(pcap_handle_group[i] != NULL)
				pcap_close(pcap_handle_group[i]);
		}
		
		if(fp != NULL)
			fclose(fp);

		//actionlist
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
   		pthread_cond_destroy(&empty);
		pthread_cond_destroy(&full);

		printf("Switch Exit...\n");
		exit(0);
		break;
	default:
		printf("error rank: %d\n", rank);
		printf("Exit...\n");
		exit(0);
		break;
	}
}

int run_switch(){
#if TEST
	printf("\nrun_switch\n");
	printf("create writers\n");
#endif
	
	int port_group[writer_num];
	for(int i = 0; i < writer_num; ++i){
		port_group[i] = i;
		int res = pthread_create(&(writer_list[i]), NULL, run_receiver, &(port_group[i]));
		if(res < 0){
			printf("pthread_create error: %d\n", res);
		}
	}
	
#if TEST
	printf("create reader\n");
#endif

	int res = pthread_create(&reader, NULL, run_reader, NULL);
	if(res < 0){
		printf("pthread_create error: %d\n", res);
	}


	for(int i = 0; i < writer_num; ++i)
	{
		pthread_join(writer_list[i], NULL);
#if TEST
		printf("pthread_join: writer %d\n", i);
#endif
	}

#if TEST	
	printf("pthread_join: reader\n");
#endif

	pthread_join(reader, NULL);
	return 0;
}

