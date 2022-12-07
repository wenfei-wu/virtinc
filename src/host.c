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
#include "util.h"

//设置pcap_loop的包处理器
void set_packet_processor(){
#if TEST
    printf("set_packet_processor\n");
#endif
   
    if(rank == RECEIVER)
        grinder = decode_and_print;
    else if(rank == SWITCH)
        grinder = run_writer;
    else{
        printf("error type: %d\n", rank);
        clean_exit();
    }
}

//打开网卡，返回ip地址
uint32_t open_pcap(char * dev_name, pcap_t ** pcap_handle){
    char errbuf[PCAP_ERRBUF_SIZE];
    uint32_t net_ip;    
    uint32_t net_mask; 
#if TEST
	printf("try to find %s\n", dev_name);
#endif
    int res = pcap_lookupnet(dev_name, &net_ip, &net_mask,  errbuf);
    if(res == -1)
    {
        printf("pcap_lookupnet(): %s\n", errbuf); 
        clean_exit();
    }

    *pcap_handle = pcap_open_live(dev_name, BUFSIZ, 1, -1, errbuf);
    if(*pcap_handle == NULL)
    { 
        printf("pcap_open_live(): %s\n", errbuf); 
        clean_exit();
    }
#if TEST
	printf("find %s successfully\n", dev_name);
#endif
    return net_ip;
}

//将字符串包装成incp数据包
void encode_incp(in_pcb_t * in_pcb , int type, int seq_num, int ack_num, char * data){
#if TEST
    printf("encode_incp\n");
#endif
    incp_header_t * incp_head = &(in_pcb->incp_head);
    incp_head->window_size = 10;//暂定
    incp_head->type = type;
    incp_head->seq_num = seq_num;
    incp_head->ack_num = ack_num;
    incp_head->length = sizeof(incp_header_t) + strlen(data);
    memcpy(in_pcb->data, data, strlen(data));
    in_pcb->data[strlen(data)] = '\0';
#if TEST
    printf("payload: %s\n", data);
    printf("payload_length: %ld\n", strlen(data));
    printf("incp_head->seq_num: %d\n", incp_head->seq_num);
    printf("incp_head->length: %d\n", incp_head->length);
#endif
}

//将incp数据包包装成ip数据包
void encode_ip(ip_pcb_t * ip_pcb, char * src_ip, char * dst_ip, char * data)
{
#if TEST
    printf("encode_ip\n");
#endif

    ip_header_t * ip_head = &(ip_pcb->ip_head);
    incp_header_t * incp_head = (incp_header_t *)data;
    ip_head->src_ip = inet_addr(src_ip);
    ip_head->dst_ip = inet_addr(dst_ip);
    ip_head->length = sizeof(ip_header_t) + incp_head->length;
    
#if TEST
    printf("payload: %s\n", ((in_pcb_t*)data)->data);
    printf("payload_length: %d\n", incp_head->length);
    printf("length_of_ip: %d\n\n", ip_head->length);
#endif

    memcpy(ip_pcb->data, data, incp_head->length);
    ((char*)ip_pcb)[ip_head->length] = '\0';
    ip_head->checksum = 0;
    ip_head->checksum = compute_checksum(ip_pcb, ip_head->length);
}

//将ip包层层剥落，将数据包信息填入packet_info中
void decode_incp_ip(packet_info_t * packet_info, char * data){
#if TEST
    printf("decode_incp_ip\n");
    printf("decode_ip\n");
#endif 
    ip_pcb_t * ip_pcb = (ip_pcb_t*)data;
    ip_header_t ip_head = ip_pcb->ip_head;
    packet_info->length_of_ip = ip_head.length;
    packet_info->src_ip = ip_head.src_ip;
#if TEST
    printf("decode_incp\n");
#endif 
    in_pcb_t * in_pcb = (in_pcb_t*)ip_pcb->data;
    incp_header_t incp_head = in_pcb->incp_head;
    packet_info->type = incp_head.type;
    packet_info->length_of_incp = incp_head.length;
    packet_info->length_of_payload = strlen(in_pcb->data);
    memcpy(packet_info->payload, in_pcb->data, packet_info->length_of_payload);    
}

//打印packet_info
void print_packet_info(packet_info_t * packet_info){
    struct in_addr src_addr;
    memcpy(&src_addr, &(packet_info->src_ip), 4);
    printf("Packet %d: from %s type %s\n", 
        packet_info->packet_id, inet_ntoa(src_addr), (packet_info->type == INCP_DATA)?"DATA":"ACK");
    printf("Length of IP: %d Length of INCP: %d\n", 
        packet_info->length_of_ip, packet_info->length_of_incp);
    printf("Length of payload: %d\nContent:%s\n\n", 
        packet_info->length_of_payload, packet_info->payload);
}   

//核验checksum，然后调用decode函数和print函数
void decode_and_print(unsigned char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content){
#if TEST
    printf("decode_and_print\n");
#endif   
    receive_packet_num++;
    if(receive_packet_num % 10 == 0)
		printf("receive_packet_num == %d\n", receive_packet_num);

    ip_header_t * ip_head = (ip_header_t *)packet_content;
    char buf[BUFFER_SIZE]={};
    memcpy(buf, packet_content, ip_head->length);
    ip_head = (ip_header_t *)buf;

    uint16_t tmp_checksum = ip_head->checksum;
    ip_head->checksum = 0;
    if(tmp_checksum != compute_checksum(buf, packet_header->len)){
        printf("Packet %d: checksum not match\n", receive_packet_num);
    }

    packet_info_t * packet_info = malloc(sizeof(packet_info_t));
    memset(packet_info, 0, sizeof(packet_info_t));
    if(packet_info == NULL){
        perror("decode_and_print: ");
        clean_exit();
    }

    pthread_mutex_lock(&packet_num_mutex);
    packet_info->packet_id = receive_packet_num;
    pthread_mutex_unlock(&packet_num_mutex);

    decode_incp_ip(packet_info, buf);

#if TEST
    print_packet_info(packet_info);
#endif 

    free(packet_info);
}

//设置包处理器，开始收包
void * run_receiver(void * arg){
#if TEST
    printf("run_receiver\n");
#endif

    set_packet_processor();
 
#if TEST
    printf("open_pcap\n");
#endif
    if(arg == NULL){//RECEIVER
        open_pcap(dev_name, &pcap_handle);
        if(pcap_loop(pcap_handle, -1, grinder, NULL) < 0)
        {
            perror("pcap_loop: ");
        }	
        if(pcap_handle != NULL)
            pcap_close(pcap_handle);
    }
    else{//SWITCH
        int idx = *((int*)arg);
#if TEST
    printf("I'm writer %d\n", idx);
#endif        
        uint32_t ip_addr = open_pcap(dev_group[idx], &(pcap_handle_group[idx]));
       
        struct in_addr addr;
        memcpy(&addr, &ip_addr, 4);

        if(pcap_loop(pcap_handle_group[idx], -1, grinder, inet_ntoa(addr)) < 0)
        {
            perror("pcap_loop: ");
        }	
        if(pcap_handle_group[idx] != NULL)
            pcap_close(pcap_handle_group[idx]);
    }     
}

// 从文件中读取字符串，调用encode函数包装之后发送
void run_sender(char * file_name, char * src, char * dst){
#if TEST
    printf("run_sender\n");
    printf("filenam:%s src:%s dst:%s\n", file_name, src, dst);
#endif
    fp = fopen(file_name, "r");
    if(fp == NULL){
        perror("run_sender(): ");
        clean_exit();
    }
#if TEST
    printf("open_file_succsesfully\n");
#endif
    char buf[BUFFER_SIZE+1];
    memset(buf, 0, sizeof(buf));
    while(fgets(buf, BUFFER_SIZE, fp) != NULL){
        if(buf[strlen(buf)-1] == '\n')
            buf[strlen(buf)-1] = '\0';
        
        in_pcb_t * in_pcb = malloc(sizeof(in_pcb_t));
        if(in_pcb == NULL){
            perror("run_sender: ");
            clean_exit();
        }
        memset(in_pcb, 0, sizeof(in_pcb_t));
        encode_incp(in_pcb, INCP_DATA, seq_num, 0, buf);

        ip_pcb_t * ip_pcb = malloc(sizeof(ip_pcb_t));
        if(ip_pcb == NULL){
            perror("run_sender: ");
            clean_exit();
        }
        memset(ip_pcb, 0, sizeof(ip_pcb_t));
        encode_ip(ip_pcb, src, dst, (char*)in_pcb);
        ip_header_t * ip_head = (ip_header_t *)ip_pcb;

        u_int32_t ipaddr = open_pcap(dev_name, &pcap_handle);
        int send_bytes = pcap_inject(pcap_handle, ip_pcb, ip_head->length);
        if(send_bytes != ip_head->length){
            printf("packet damage: sendbytes = %d length_of_ip = %d\n", 
                                    send_bytes, ip_head->length);
        }
        seq_num++;
        send_packet_num++;
        if(send_packet_num % 10 == 0)
			printf("send_packet_num = %d\n", send_packet_num);
        free(ip_pcb);
        free(in_pcb);
        memset(buf, 0, sizeof(buf));
    }
    if(pcap_handle != NULL)
        pcap_close(pcap_handle);
    fclose(fp);
}

//终端主机rank识别，dev分配，调用run
void run_host(int identity, char * file_name){
    rank = identity;
    if(rank == RECEIVER){
        dev_name = "host2-iface1";
        run_receiver(NULL);
    }else if(rank == SENDER){
        dev_name = "host1-iface1";
        run_sender(file_name, "10.0.0.1", "10.0.1.1");
    }
}