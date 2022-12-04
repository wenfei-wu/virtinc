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

#include "net.h"

//循环读文件，调用parserule并往action_list里面加节点
void parse_rulefile(char * file_name){
	fp = fopen(file_name, "r");
	if(fp == NULL){
		perror("parse_rulefile()");
		clean_exit();
	}

	action_list = malloc(sizeof(rule_t));
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
		parse_rule(current, buf);
		prev->next = current;
		prev = current;

		memset(buf, 0, sizeof(buf));
	}

	fclose(fp);
}

//解析rule_str，填入rule
void parse_rule(rule_t * rule, char * rule_str){
	int num1, num2, num3, num4, output_port;
	char * ipaddr;

	sscanf(rule_str, "Match(%d.%d.%d.%d):Action(%d)", 
			&num1, &num2, &num3, &num4, &output_port);
	sprintf(ipaddr, "%d.%d.%d.%d", num1, num2, num3, num4);

	rule->output_port = output_port;
	rule->src_ip = inet_addr(ipaddr);
	rule->next = NULL;
}

//打印actio_list
void print_rulelist(){
	rule_t * prev, * current;
	prev = action_list;

	while(prev->next != NULL){
		current = prev->next;
		struct in_addr ipaddr;
		memcpy(&ipaddr, &(current->src_ip), 4);
		
		printf("Match(%s):Action(%d)\n", inet_ntoa(ipaddr), current->output_port);

		prev = current;
	}
}

//dev_group初始化
void init_port(){
	for(int i = 0; i < port_num; ++i){
		sprintf(dev_group[i], "switch-iface%d", i+1);
	}
}

//缓冲区初始化
void init_buffer(){
	used_slot_head = malloc(sizeof(ip_pcb_t));
	unused_slot_head = malloc(sizeof(ip_pcb_t));
	memset(used_slot_head, 0, sizeof(ip_pcb_t));
	memset(unused_slot_head, 0, sizeof(ip_pcb_t));

	used_slot_head->next = NULL;
	ip_pcb_t * prev, * current;
	prev = unused_slot_head;

	for(int i = 0; i < SLOT_NUM; ++i){
		current = malloc(sizeof(ip_pcb_t));
		current->next = NULL;
		prev = current;
	}
}

//tbc
int init_switch(int argc, char** argv){
	rank = SWITCH;
	port_num = atoi(argv[2]);

	if(argc >= 4)
		parse_rulefile(argv[3]);
	else
		parse_rulefile("/home/pumpkin/桌面/mynet/src/switch.config");

	init_port();
	init_buffer();

	//

	return 0;
}

//tbc
void check_and_write(unsigned char *argument, const struct pcap_pkthdr *packet_heaher, const unsigned char *packet_content){
	packet_num++;

    char buf[BUFFER_SIZE]={};
    ip_header_t * ip_head = (ip_header_t *)packet_content;
    memcpy(buf, packet_content, ip_head->length);
    ip_head = (ip_header_t *)buf;

    int tmp_checksum = ip_head->checksum;
    ip_head->checksum = 0;
    if(tmp_checksum != compute_checksum(buf, ip_head->length)){
        printf("packet %d: checksum not match", packet_num);
		return;
    }

	//获得锁然后写入缓冲区
	return;
}

int match_and_send(char * data){
	packet_info_t * packet_info = malloc(sizeof(packet_info_t));
	decode_incp_ip(packet_info, data);

	rule_t * prev_rule = action_list;
	rule_t *curr_rule = prev_rule->next;
	while(curr_rule != NULL){
		if(curr_rule->src_ip == packet_info->src_ip){
			open_pcap(dev_group[curr_rule->output_port]);

			int send_bytes = pcap_inject(pcap_handle, data, packet_info->length_of_ip);
			if(send_bytes != packet_info->length_of_ip){
				printf("packet damage: sendbytes = %d length_of_ip = %d\n", 
										send_bytes, packet_info->length_of_ip);
        	}

			return 1;
		}
		prev_rule = curr_rule;
		curr_rule = prev_rule->next;
	}
	return 0;
}

//tbc
void run_deamon(){

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

		printf("total received packet: %d\n", packet_num);
		printf("Receiver Exit...\n");

		exit(0);
		break;
	case SENDER:
		if(pcap_handle != NULL)
			pcap_close(pcap_handle);
		if(fp != NULL)
			fclose(fp);

		printf("total sended packet: %d\n", packet_num);
		printf("Sender Exit...\n");

		exit(0);
		break;
	case SWITCH:
		if(pcap_handle != NULL)
			pcap_close(pcap_handle);
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

		//锁和进程tbc

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
	return 0;
}

