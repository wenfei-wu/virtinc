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
    if(rank == RECEIVER)
        grinder = decode_and_print;
    else if(rank == SWITCH)
        grinder = check_and_write;
    else{
        printf("error type: %d\n", rank);
        clean_exit();
    }
}

//打开网卡，返回ip地址
uint32_t open_pcap(char * dev_name){
    char errbuf[PCAP_ERRBUF_SIZE];
    uint32_t net_ip;    //网络地址
    uint32_t net_mask;    //子网掩码
    
    int res = pcap_lookupnet(dev_name, &net_ip, &net_mask,  errbuf);
    if(res == -1)
    {
        printf("pcap_lookupnet(): %s\n", errbuf); 
        clean_exit();
    }

    pcap_handle = pcap_open_live(dev_name, BUFSIZ, 1, -1, errbuf);
    if(pcap_handle == NULL)
    { 
        printf("pcap_open_live(): %s\n", errbuf); 
        clean_exit();
    }

    return net_ip;
}

//将字符串包装成incp数据包
void encode_incp(in_pcb_t * in_pcb , int type, int seq_num, int ack_num, char * data){
    incp_header_t * incp_head = (incp_header_t*)in_pcb;
    incp_head->type = type;
    incp_head->seq_num = seq_num;
    incp_head->ack_num = ack_num;
    incp_head->length = sizeof(incp_header_t) + strlen(data);
    incp_head->window_size = icb->window_size;
    memcpy(in_pcb->data, data, strlen(data));
    ((char*)in_pcb)[incp_head->length] = '\0';
}

//将incp数据包包装成ip数据包
void encode_ip(ip_pcb_t * ip_pcb, char * src_ip, char * dst_ip, char * data)
{
    ip_header_t * ip_head = (ip_header_t*)ip_pcb;
    ip_head->version = 4;
    ip_head->headlen = 5;

    ip_head->src_ip = inet_addr(src_ip);
    ip_head->dst_ip = inet_addr(dst_ip);
    ip_head->length = ip_head->headlen + strlen(data);
    memcpy(ip_pcb->data, data, strlen(data));
    ((char*)ip_pcb)[ip_head->length] = '\0';
    ip_head->checksum = 0;
    ip_head->checksum = compute_checksum(ip_pcb, ip_head->length);
}

//将ip包层层剥落，将数据包信息填入packet_info中
void decode_incp_ip(packet_info_t * packet_info, char * data){
    packet_info->packet_id = packet_num;

    ip_pcb_t * ip_pcb = (ip_pcb_t*)data;
    ip_header_t * ip_head = (ip_header_t*)ip_pcb;
    packet_info->length_of_ip = ip_head->length;
    packet_info->src_ip = ip_head->src_ip;

    in_pcb_t * in_pcb = (in_pcb_t*)ip_pcb->data;
    incp_header_t * incp_head = (incp_header_t *)in_pcb;
    packet_info->type = incp_head->type;
    packet_info->length_of_incp = incp_head->length;
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
    packet_num++;

    char buf[BUFFER_SIZE]={};
    ip_header_t * ip_head = (ip_header_t *)packet_content;
    memcpy(buf, packet_content, ip_head->length);
    ip_head = (ip_header_t *)buf;

    int tmp_checksum = ip_head->checksum;
    ip_head->checksum = 0;
    if(tmp_checksum != compute_checksum(buf, ip_head->length)){
        printf("packet %d: checksum not match", packet_num);
    }

    packet_info_t * packet_info = malloc(sizeof(packet_info_t));
    if(packet_info == NULL){
        perror("decode_and_print: ");
        clean_exit();
    }
    decode_incp_ip(packet_info, buf);
    print_packet_info(packet_info);

    free(packet_info);
}

//设置包处理器，开始收包
void run_receiver(){
    set_packet_processor();

    open_pcap(dev_name);

    if(pcap_loop(pcap_handle, -1, grinder, NULL) < 0)
	{
    	perror("pcap_loop: ");
	}	

	pcap_close(pcap_handle);
}

// 从文件中读取字符串，调用encode函数包装之后发送
void run_sender(char * file_name, char * src, char * dst){
    fp = fopen(file_name, "r");
    if(fp == NULL){
        perror("run_sender(): ");
        clean_exit();
    }

    char buf[BUFFER_SIZE+1];
    memset(buf, 0, sizeof(buf));
    while(fgets(buf, BUFFER_SIZE, fp) != NULL){
        if(buf[strlen(buf)-1]=='\n')
            buf[strlen(buf)-1] = '\0';
        
        in_pcb_t * in_pcb = malloc(sizeof(in_pcb_t));
        encode_incp(in_pcb, INCP_DATA, seq_num, 0, buf);

        ip_pcb_t * ip_pcb = malloc(sizeof(ip_pcb_t));
        encode_ip(ip_pcb, src, dst, (char*)in_pcb);
        ip_header_t * ip_head = (ip_header_t *)ip_pcb;

        u_int32_t ipaddr = open_pcap(dev_name);
        int send_bytes = pcap_inject(pcap_handle, ip_pcb, ip_head->length);
        if(send_bytes != ip_head->length){
            printf("packet damage: sendbytes = %d length_of_ip = %d\n", 
                                    send_bytes, ip_head->length);
        }
        packet_num++;
        free(ip_pcb);
        free(in_pcb);
        memset(buf, 0, sizeof(buf));
    }
    fclose(fp);
}

//终端主机rank识别，dev分配，调用run
void run_host(int identity, char * file_name){
    rank = identity;
    if(rank == RECEIVER){
        dev_name = "host1-iface1";
        run_sender(file_name, "10.0.0.1", "10.0.1.1");
    }else if(rank == SENDER){
        dev_name = "host2-iface1";
        run_receiver();
    }
}