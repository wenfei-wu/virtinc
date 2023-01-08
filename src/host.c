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

#include "net.h"
#include "util.h"

//设置pcap_loop的包处理器
void  set_packet_processor(){
#if TEST
    printf("set_packet_processor\n");
#endif
    if(rank == RECEIVER || rank == SENDER)
        grinder = write_receive_buffer;
    else if(rank == SWITCH || rank == UNBLOCK_SWITCH)
        grinder = write_buffer;
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
void encode_incp(in_pcb_t * in_pcb , int seq_num, char * data, int payload_length, int offset){
#if TEST
    printf("encode_incp\n");
#endif
    incp_header_t * incp_head = &(in_pcb->incp_head);
    incp_head->seq_num = seq_num;
    if(seq_num == 0){
        incp_head->msg_head = 1;
#if TEST
        printf("first packet of the message\n");
#endif
    }

    if(payload_length < INCP_PAYLOAD)
    {   
        incp_head->msg_tail = 1;
#if TEST
        printf("last packet of the message\n");
#endif
    }

    incp_head->offset = offset;
    incp_head->ack_flag = 0;
    incp_head->payload_length = payload_length;
    incp_head->conn_id = current_task->conn_id;
    memcpy(in_pcb->data, data, payload_length);
    in_pcb->data[payload_length] = '\0';
#if TEST
    printf("seq_num = %d\n\n", incp_head->seq_num);
    /*printf("incp_head->payload_length: %d\n", payload_length);
    printf("incp_head->offset: %d\n", offset);
    printf("left_size: %d\n", current_task->left_size);
    printf("payload: %s\n", data);*/
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
    ip_head->length = sizeof(ip_header_t) + sizeof(incp_header_t) + incp_head->payload_length;
    
 /*if TEST
    printf("payload: %s\n", ((in_pcb_t*)data)->data);
    printf("payload_length: %ld\n", sizeof(incp_header_t) + incp_head->payload_length);
    printf("length_of_ip: %d\n\n", ip_head->length);
#endif*/

    memcpy(ip_pcb->data, data, sizeof(incp_header_t) + incp_head->payload_length);
    ((char*)ip_pcb)[ip_head->length] = '\0';
    ip_head->checksum = 0;
    ip_head->checksum = compute_checksum(ip_pcb, ip_head->length);
}

//将ip包层层剥落，将数据包信息填入packet_info中
void decode_incp_ip(packet_info_t * packet_info, const unsigned char * data){
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
    packet_info->type = incp_head.ack_flag;
    packet_info->seq_num = incp_head.seq_num;
    packet_info->length_of_payload = incp_head.payload_length;
    packet_info->offset = incp_head.offset;
    memcpy(packet_info->payload, in_pcb->data, packet_info->length_of_payload);    
}

//打印packet_info
void print_packet_info(packet_info_t * packet_info){
    struct in_addr src_addr;
    memcpy(&src_addr, &(packet_info->src_ip), 4);
    printf("Packet %d: from %s type %s\n", 
        packet_info->packet_id, inet_ntoa(src_addr), (packet_info->type == INCP_DATA)?"DATA":"ACK");
    printf("seq_num: %d offset: %d\n", packet_info->seq_num, packet_info->offset);
    printf("Length of payload: %d\nContent:%s\n\n", 
        packet_info->length_of_payload, packet_info->payload);
}   

// 核验checksum，然后调用decode函数和print函数
void decode_and_print(unsigned char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content){
#if TEST
    printf("decode_and_print\n");
#endif   
    receive_packet_num++;
    if(receive_packet_num % 50 == 0)
		printf("receive_packet_num = %d\n", receive_packet_num);

    if(!check(packet_content)){
        printf("Packet %d: checksum not match\n", receive_packet_num);
        //return;
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

    decode_incp_ip(packet_info, packet_content);

#if TEST
    print_packet_info(packet_info);
#endif 

    free(packet_info);
}

//checksum验证，错误返回0，否则返回1
int check(const unsigned char *packet_content){
    ip_header_t * ip_head = (ip_header_t *)packet_content;
    char buf[BUFFER_SIZE]={};
    memcpy(buf, packet_content, ip_head->length);
    ip_head = (ip_header_t *)buf;

    uint16_t tmp_checksum = ip_head->checksum;
    ip_head->checksum = 0;
    if(tmp_checksum != compute_checksum(buf, ip_head->length)){
        return 0;
    }
    return 1;
}

// 接收线程接收到数据之后写入缓冲区
void write_receive_buffer(unsigned char *argument, const struct pcap_pkthdr *packet_header, const unsigned char *packet_content){
#if TEST
    printf("receive packet\n");
#endif

    // 接收包统计
    receive_packet_num++;
    if(receive_packet_num % 50 == 0)
		printf("receive_packet_num = %d\n", receive_packet_num);

    // checksum计算
    if(!check(packet_content)){
        printf("Packet %d: checksum not match\n", receive_packet_num);
        //return;
    }

    // 写入缓冲区
    ip_pcb_t * current = malloc(sizeof(ip_pcb_t));
    memset(current, 0, sizeof(current));
    memcpy(current, packet_content, packet_header->len);

    pthread_mutex_lock(&receive_buffer_mutex);
    last_receive_buffer->next = current;
    last_receive_buffer = current;
    last_receive_buffer->next = NULL;
    pthread_mutex_unlock(&receive_buffer_mutex);
}

// 将incp报文包装成ip报文，加入缓冲区
// 如果缓冲区满了返回-1
int write_send_buffer(in_pcb_t * current){
#if TEST
    printf("write_send_buffer\n");
#endif
    if(full_num >= MAX_SEND_BUF)
        return -1;

    // 包装incp报文
    ip_pcb_t * ip_pcb = malloc(sizeof(ip_pcb_t));
    memset(ip_pcb, 0, sizeof(ip_pcb_t));
    encode_ip(ip_pcb, current_task->src_ip, current_task->dst_ip, (char*)current);

    // 插入缓冲区末尾
    last_send_buffer->next = ip_pcb;
    last_send_buffer = ip_pcb;
    full_num++;

    return 0;
}

// 接收方回复ack
int reply_ack(in_pcb_t * in_pcb){
#if TEST
    printf("reply_ack: ");
#endif
    // 取出缓冲区消息块
    pthread_mutex_lock(&receive_buffer_mutex);
    ip_pcb_t * current = receive_buffer_head->next;
    receive_buffer_head->next = current->next;
    if(current->next == NULL)
        last_receive_buffer = receive_buffer_head;
    pthread_mutex_unlock(&receive_buffer_mutex);

    // 交换dst、src
    ip_header_t * ip_head = (ip_header_t *)current;
    uint32_t src_ip = ip_head->src_ip;
    ip_head->src_ip = ip_head->dst_ip;
    ip_head->dst_ip = src_ip;

    // 设置ack_flag
    incp_header_t * incp_head = (incp_header_t *)(current->data);
    incp_head->ack_flag = 1;
#if TEST
    printf("seq_num = %d conn_id = %d\n\n", incp_head->seq_num, incp_head->conn_id);
#endif
    // 重新计算checksum
    ip_head->checksum = 0;
    ip_head->checksum = compute_checksum(current, ip_head->length);

    // 发送
    int send_bytes = pcap_inject(pcap_handle, current, ip_head->length);
    if(send_bytes != ip_head->length){
        printf("packet damage: sendbytes = %d length_of_ip = %d\n", 
                                send_bytes, ip_head->length);
        return -1;
    }

    memset(in_pcb, 0, sizeof(in_pcb_t));
    memcpy(in_pcb, current->data, incp_head->payload_length + sizeof(incp_header_t));
    free(current);
    return 0;
}

// loop接收，调用grinder
void * run_receive_daemon(){
#if TEST
    printf("run_receive_daemon\n");
#endif 
    set_packet_processor();

#if TEST
    printf("open_pcap\n");
#endif
    if(pcap_loop(pcap_handle, -1, grinder, NULL) < 0)
    {
        perror("pcap_loop: ");
    }	
}

// 根据收到的data包current，进行窗口处理
int process_receive_window(in_pcb_t * current){
#if TEST
    printf("process_receive_window:\n");
#endif
    incp_header_t * incp_head = (incp_header_t *)current;
    struct recv_state * current_state = &(recv_states[incp_head->conn_id]);
    int conn_id = MAX_CONN_NUM;
    int idx = incp_head->seq_num % (2*MAX_WND_SIZE);


    if(current_state->recv_until == -1 && incp_head->msg_head == 1){// recv_until没有初始化，接收到第一个报文
#if TEST
    printf("first packet of the sequence\n");
#endif
        current_state->recv_until = incp_head->seq_num;
    }
    else if((incp_head->seq_num - current_state->recv_until > MAX_WND_SIZE) ||
            (current_state->recv_until != -1 && incp_head->seq_num <= current_state->recv_until) ||
            (current_state->recv_window[idx] == 1)){// seq_num不在窗口中或者接受过了   
        return -1;
    }


    if(incp_head->msg_tail == 1){// 记录任务的最后一个packet序号
#if TEST
        printf("last packet of the sequence: seq_num = %d conn_id = %d\n", current_state->conn_id, incp_head->seq_num);
#endif   
        current_state->last_seq_of_current_task = incp_head->seq_num;    
    }
 
    // 清空可能窗口以外的bit
    current_state->recv_window[(idx + MAX_WND_SIZE) % (2*MAX_WND_SIZE)] = 0;

    // 设置recv_flag
    current_state->recv_window[idx] = 1;

    // payload写到缓冲区
    char * dst_addr = (char*)(current_state->addr)+incp_head->offset;
    memcpy(dst_addr, current->data, incp_head->payload_length);

    // 窗口滑动
    int new_recv_until = current_state->recv_until + 1;
    while(new_recv_until - current_state->recv_until <= MAX_WND_SIZE &&
            current_state->recv_window[new_recv_until % (2*MAX_WND_SIZE)] == 1){
        current_state->recv_window[new_recv_until % (2*MAX_WND_SIZE)] = 0;
        new_recv_until++;
    }
    current_state->recv_until = new_recv_until - 1;
    if(current_state->last_seq_of_current_task != -1 &&
        current_state->recv_until == current_state->last_seq_of_current_task)
        conn_id = current_state->conn_id;

#if TEST
    printf("receive window slide: recv_until = %d\n", current_state->recv_until);
#endif 

    return conn_id;
}

// 根据收到的ack包current，进行窗口处理
int process_send_window(){
#if TEST
    printf("\nprocess_send_window\n");
#endif
    /* 读取缓冲区报文（都是ack报文）
        根据找到对应的连接的状态，更新ack_wnd，更新窗口
    */
    // 取出缓冲区消息块
    pthread_mutex_lock(&receive_buffer_mutex);
    ip_pcb_t * current = receive_buffer_head->next;
    receive_buffer_head->next = current->next;
    if(receive_buffer_head->next == NULL)
        last_receive_buffer = receive_buffer_head;
    pthread_mutex_unlock(&receive_buffer_mutex);

    incp_header_t * incp_head = (incp_header_t *)(current->data);
    int conn_id = MAX_CONN_NUM;

    int idx = incp_head->seq_num % (2*MAX_WND_SIZE);

#if TEST
    printf("seq_num = %d, idx = %d\n", incp_head->seq_num, idx);
#endif
    if((send_state.ack_until == -1) && (incp_head->msg_head == 1)){// recv_until没有初始化，接收到第一个报文
        send_state.ack_until = incp_head->seq_num;
#if TEST
        printf("first packet of the sequence\n");
#endif
    }
    else if((incp_head->seq_num - send_state.ack_until > MAX_WND_SIZE) ||
            (send_state.ack_until != -1 && incp_head->seq_num <= send_state.ack_until) ||
            (send_state.ack_window[idx].incp_head.ack_flag == 1)){// seq_num不在窗口中或者接受过了  
        return -1;
    }
    if(incp_head->msg_tail == 1){// 记录任务的最后一个packet序号
        send_state.last_seq_of_current_task = incp_head->seq_num;
#if TEST
    printf("last packet of the sequence: seq_num = % d conn_id = %d\n", incp_head->seq_num, current_task->conn_id);
#endif     
    }

    free(current);

    // 清空可能窗口以外的bit
    send_state.ack_window[(idx + MAX_WND_SIZE) % (2*MAX_WND_SIZE)].incp_head.ack_flag = 0;

    // 设置ack_flag
    send_state.ack_window[idx].incp_head.ack_flag = 1;

    // 窗口滑动
    int new_ack_until = send_state.ack_until + 1;
    incp_header_t * tmp_incp_head = &(send_state.ack_window[new_ack_until % (2*MAX_WND_SIZE)].incp_head);
    while(new_ack_until - send_state.ack_until <= MAX_WND_SIZE &&
            tmp_incp_head->ack_flag == 1){
        tmp_incp_head->ack_flag = 0;
        new_ack_until++;
        tmp_incp_head = &(send_state.ack_window[new_ack_until % (2*MAX_WND_SIZE)].incp_head);
    }
    send_state.ack_until = new_ack_until - 1;
    if(send_state.last_seq_of_current_task != -1 &&
        send_state.ack_until == send_state.last_seq_of_current_task)
        conn_id = incp_head->conn_id;
#if TEST
    printf("send window slide: ack_until = %d\n\n", send_state.ack_until);
#endif 
    return conn_id;
}

// current_task赋值
void set_task(){
    if(current_task == NULL){
        pthread_mutex_lock(&task_mutex);

        printf("task_num = %d\n", task_num);

        while (task_num == 0){
            pthread_cond_wait(&task_queue_empty, &task_mutex);
        }
#if TEST
        printf("find new task\n");
#endif
        // 取出task
        current_task = task_queue->next;
#if TEST
        printf("current_task\n");
#endif
        task_queue->next = current_task->next;
#if TEST
        printf("task_queue\n");
#endif
        if(task_queue->next == NULL)
            last_task = task_queue;
        task_num--;
        pthread_cond_signal(&task_queue_full);
        pthread_mutex_unlock(&task_mutex);
        init_conn(current_task->conn_id);
    }
}

// 检查超时报文并添加到发送缓冲区
void check_timeout(){
    int tmp_seq = send_state.ack_until+1;
    int time_now = clock();
    if(send_state.last_sent != -1){
        while(tmp_seq <= send_state.last_sent){
            int idx = tmp_seq % (2*MAX_WND_SIZE);
            if(send_state.ack_window[idx].incp_head.ack_flag == 0 &&
                time_now - send_state.ack_window[idx].time_stamp > MAX_DELAY){
#if TEST
    printf("check_timeout\n");
    printf("tmp_seq: %d \n", tmp_seq);
#endif
                int res = write_send_buffer(&(send_state.ack_window[idx]));
                if(res < 0){// 发送缓冲区已满
                    break;
                }
                send_state.ack_window[idx].time_stamp = clock();
            }
            tmp_seq++;
        }
    }
}

// 取出字符串制作新的报文并添加到发送缓冲区
void make_new_packet(){
    int tmp_seq = send_state.last_sent+1;
    while((tmp_seq - send_state.ack_until <= MAX_WND_SIZE) && (current_task->left_size > 0)){
#if TEST
    printf("\nmake_new_packet\n");
#endif   
        int idx = tmp_seq % (2*MAX_WND_SIZE);
        int offset = tmp_seq * INCP_PAYLOAD;
        char * data = (char *)current_task->addr + offset;
        int payload_length;

        // 判断剩余数据长度
        if(current_task->left_size - INCP_PAYLOAD >= 0){
            payload_length = INCP_PAYLOAD;
            current_task->left_size -= INCP_PAYLOAD;
        }else{
            payload_length = current_task->left_size;
            current_task->left_size = 0;
        }

        // 包装并插入缓冲区
        send_state.last_sent = tmp_seq;
        encode_incp(&(send_state.ack_window[idx]), tmp_seq, data, payload_length, offset);
        int res = write_send_buffer(&(send_state.ack_window[idx]));
        if(res < 0){// 发送缓冲区已满
            break;
        }
        tmp_seq++;
    }
}

// 发送缓冲区所有报文并设置时间戳
void send_buffer_packet(){
    ip_pcb_t * current = send_buffer_head->next;
    while(current != NULL){
#if TEST
        printf("\nsend packet\n");
#endif
        send_packet_num++;
        int send_bytes = pcap_inject(pcap_handle, current, ((ip_header_t*)current)->length);
        if(send_bytes != ((ip_header_t*)current)->length){
            printf("packet damage: sendbytes = %d length_of_ip = %d\n", 
                                    send_bytes, ((ip_header_t*)current)->length);
            clean_exit();
        }
        // 设置时间戳
        incp_header_t * incp_head = (incp_header_t *)(current->data);
        int idx = incp_head->seq_num % (2*MAX_WND_SIZE);
        send_state.ack_window[idx].time_stamp = clock();

        // 释放缓冲区
        full_num--;
        send_buffer_head->next = current->next;
        free(current);
        current = send_buffer_head->next;
        if(current == NULL)
            last_send_buffer = send_buffer_head;
    }
}

// sender的处理daemon函数：读取缓冲区报文（ack），处理window，从task发送新的报文
void * run_sender_process_daemon(){
#if TEST
    printf("run_sender_process_daemon！\n");
#endif

    while(1){
        // 读取缓冲区ack包，进行窗口调整
        while(receive_buffer_head->next != NULL){
            // 查找对应连接并更新窗口状态
            int conn_id;
            if((conn_id = process_send_window()) < 0){
                printf("process_send_window: drop error packet\n");
            }else if(conn_id != MAX_CONN_NUM){
                // 说明是最后一个包，返回conn_id
                send_ipc(conn_id, "send finish");
                free(current_task);
                current_task = NULL;
            }
        }
        
        // 取出task并进行连接初始化
        set_task();
        
        // 检查超时报文
        check_timeout();
  
        // 检查窗口剩余报文（填满窗口）
        make_new_packet();

        // 发送缓冲区所有报文
        send_buffer_packet();
    }  
}

// receiver的处理daemon函数：读取缓冲区报文（data），发送ack，处理window，向receiver报告接收完毕
void * run_receiver_process_daemon(){
#if TEST
    printf("run_receiver_process_daemon\n");
#endif 
    while(1){
        if(receive_buffer_head->next != NULL){
            in_pcb_t * current = malloc(sizeof(in_pcb_t));

            // 回复ack并获得incp报文
            if(reply_ack(current) < 0)
                printf("send fail!\n");

            // 查找对应连接并更新窗口状态
            int conn_id = process_receive_window(current);
            free(current);
            if(conn_id >= 0 && conn_id != MAX_CONN_NUM){
                send_ipc(conn_id, "receive finish");
            }
        }
    }
#if TEST
    printf("process daemon end\n");
#endif 
}

// 建立连接，初始化连接状态
int init_conn(int conn_id){
    // conn_id对应数组序号
    if(rank == SENDER){
        send_state.conn_id = conn_id;
        send_state.last_sent = -1;
        //send_state.last_acked = -1;
        send_state.ack_until = -1;
        send_state.last_seq_of_current_task = -1;
        memset(send_state.ack_window, 0, sizeof(send_state.ack_window));

    }else if(rank == RECEIVER){
        recv_states[conn_id].conn_id = conn_id;
        recv_states[conn_id].recv_until = -1;
        recv_states[conn_id].last_seq_of_current_task = -1;
        recv_states[conn_id].addr = NULL;
        recv_states[conn_id].size = 0;
    }else{
        printf("error type\n");
        clean_exit();
    }
    return 0;
}

// 初始化任务队列
void init_task_queue(){
#if TEST
    printf("init_task_queue!\n");
#endif
    // 锁
    pthread_mutex_init(&task_mutex, NULL);
    // 虚拟队列头部
    task_queue = malloc(sizeof(task_t));
    memset(task_queue, 0, sizeof(task_queue));
    task_queue->conn_id = -1;
    last_task = task_queue;
}

// 监听消息队列，消息类型为conn_id+1
int listen_ipc(int conn_id){
#if TEST
    printf("listen_ipc: connid = %d\n", conn_id);
#endif
    int msgqid;
    key_t key = ftok("incp", conn_id+1);
    msgqid = msgget(key , IPC_EXCL);  /*检查消息队列是否存在*/  
    if(msgqid < 0){  
        msgqid = msgget(key, IPC_CREAT|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);/*创建消息队列*/  
        if(msgqid < 0){  
            perror("get ipc_id error: ");
            clean_exit();
        }  
    }   

    ipc_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.msgtype = conn_id + 1;

    // msgflg参数设置为0，阻塞式接收消息
    int res = msgrcv(msgqid, &msg, IPC_MSG_SIZE, msg.msgtype, 0);
    if (res < 0) {
        perror("msgrcv error");
        return -1;
    }else{
        printf("recv finish\n");
    }

    printf("type = %ld, message = %s\n", msg.msgtype, msg.msgtext) ;


    return 0;
}

// 向消息队列发送消息，消息类型为conn_id+1
int send_ipc(int conn_id, char * text){
#if TEST
    printf("send_ipc\n");
#endif
    
    key_t key = ftok("incp", conn_id+1);
    int msgqid = msgget(key, IPC_CREAT|S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH) ;
    if (msgqid < 0) {
        perror("get ipc_id error: ") ;
        clean_exit();
    }

    ipc_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.msgtype = conn_id + 1;
    strcpy(msg.msgtext, text);
    // msgflg参数设置为0，阻塞式发送消息
    int res = msgsnd(msgqid, &msg, IPC_MSG_SIZE, 0);
    if (res < 0) {
        perror("msgrcv error");
        return -1;
    }else{
        printf("send finish\n");
    }

    printf("type = %ld, message = %s\n", msg.msgtype, msg.msgtext) ;


    return 0;
}

// 构造发送任务，加入队列，监听
int incp_send(int conn_id, void *addr, unsigned int size, char * src_ip, char * dst_ip){
#if TEST
    printf("incp_send!\n");
#endif
    // 构造task
    task_t * new_task = malloc(sizeof(task_t));
    memset(new_task, 0, sizeof(task_t));

    new_task->conn_id = conn_id;
    new_task->addr = addr;
    new_task->size = size;
    new_task->left_size = size;
    new_task->src_ip = src_ip;
    new_task->dst_ip = dst_ip;

#if TEST
    printf("insert task queue\n");
#endif
    // 加入任务队列
    // full和empty两把锁/暂时设定task_queue无限大
    pthread_mutex_lock(&task_mutex);
    while(task_num == MAX_TASK_NUM){
        pthread_cond_wait(&task_queue_full, &task_mutex);
    }

    task_num++;
    last_task->next = new_task;
    last_task = new_task;
    pthread_cond_signal(&task_queue_empty);
    pthread_mutex_unlock(&task_mutex);

#if TEST
    printf("wait for reply\n");
#endif
    // 监听等待回复
    return listen_ipc(conn_id);
}

// 构造recv_state，监听
int incp_recv(int conn_id, void *addr, unsigned int size){
#if TEST
    printf("incp_recv\n");
#endif
    init_conn(conn_id);

    recv_states[conn_id].addr = addr;
    recv_states[conn_id].size = size;

    return listen_ipc(conn_id);
}

void host_end(){
    if(rank == 0){
        pthread_kill(sender_process_daemon, SIGALRM);
        pthread_kill(receive_daemon, SIGALRM);
    }else if(rank == 2){
        pthread_kill(receiver_process_daemon, SIGALRM);
        pthread_kill(receive_daemon, SIGALRM);
    }else if(rank == 1){
        for(int i = 0; i < writer_num; ++i){
            pthread_kill(writer_list[i], SIGALRM);
        }
        pthread_kill(reader, SIGALRM);
    }
}

void daemon_end(){
    pthread_exit(NULL);
}

// host2运行：初始化recv_state, 运行receive线程
void run_host2(int argc, char** argv){
    signal(SIGALRM, daemon_end); 
    signal(SIGTERM, host_end);
    // 连接数
    conn_num = atoi(argv[2]);

    // pcap初始化
    dev_name = "host2-iface1";
    open_pcap(dev_name, &pcap_handle);

    init_buffer();
    pthread_mutex_init(&receive_buffer_mutex, NULL);

    // 运行处理线程和接收线程
    int res = pthread_create(&receiver_process_daemon, NULL, run_receiver_process_daemon, NULL);
    if(res < 0){
        printf("pthread_create error: %d\n", res);
        clean_exit();
    }
    res = pthread_create(&receive_daemon, NULL, run_receive_daemon, NULL);
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
}



// host1运行：初始化send_state, 运行sender线程
void run_host1(int argc, char** argv){
    signal(SIGALRM, daemon_end); 
    signal(SIGTERM, host_end);
    char * src = "10.0.0.1";
    char * dst = "10.0.1.1";
    char * file_name = "text.txt";

    // pcap初始化
    dev_name = "host1-iface1";
    open_pcap(dev_name, &pcap_handle);

    //task_queue
    init_task_queue();

    //buffer
    init_buffer();

    // 连接数
    conn_num = atoi(argv[2]);
    

    // 锁和条件变量
    pthread_mutex_init(&fp_mutex, NULL);
    pthread_mutex_init(&receive_buffer_mutex, NULL);
    pthread_mutex_init(&task_mutex, NULL);
    pthread_cond_init(&task_queue_empty, NULL);
	pthread_cond_init(&task_queue_full, NULL);


    // 运行处理线程和接收线程
    int res = pthread_create(&sender_process_daemon, NULL, run_sender_process_daemon, NULL);
    if(res < 0){
        printf("pthread_create error: %d\n", res);
        clean_exit();
    }
    res = pthread_create(&receive_daemon, NULL, run_receive_daemon, NULL);
    if(res < 0){
        printf("pthread_create error: %d\n", res);
        clean_exit();
    }

    // 运行sender_list
    struct arg_t arg_group[MAX_CONN_NUM] = {};
    for(int i = 0; i < conn_num; ++i){ 
        arg_group[i].conn_id = i;
        strcpy(arg_group[i].file_name, file_name); 
        strcpy(arg_group[i].src_ip, src);
        strcpy(arg_group[i].dst_ip, dst);    
        int res = pthread_create(&(sender_list[i]), NULL, run_sender, &(arg_group[i]));
        if(res < 0){
            printf("pthread_create error: %d\n", res);
            clean_exit();
        }
    }

    //回收线程和内存
    for(int i = 0; i < conn_num; ++i){
        pthread_join(sender_list[i], NULL);
    }
#if TEST
    printf("pthread_join sender_list finish\n");
#endif
   

    pthread_join(sender_process_daemon, NULL);
    pthread_join(receive_daemon, NULL);

#if TEST
    printf("pthread_join daemon finish\n");
#endif
    clean_exit();
}

// 循环阻塞
void * run_receiver(void * arg){
#if TEST
    printf("run_receiver\n");
#endif
    // 接收字符串的大小
    FILE * fp = fopen("text.txt", "r");
    fseek(fp, 0, SEEK_END);
    int file_size = ftell(fp)+1;
    char * buf = (char *)malloc(file_size);
    memset(buf, 0, file_size);
    fclose(fp);

    // 接收信息
    int conn_id = *((int*)arg);
    int res = incp_recv(conn_id, buf, file_size);
    if(res < 0){
        printf("recv error\n");
    }else{

        buf[file_size-1] = '\0';
        // 写到对应文件中去:output_($connid).txt
        char output_file[NAME_SIZE]={};
        sprintf(output_file, "output_%d.txt", conn_id);
        fp = fopen(output_file, "w");
        fwrite(buf, sizeof(char), file_size, fp);
        
        fclose(fp);
        printf("receiver end\n");
    }

}

// 从文件中读取字符串，调用send进入发送阻塞
void * run_sender(void * arg){

    struct arg_t * argument = (struct arg_t *)arg;

#if TEST
    printf("run_sender\n");
    printf("file_name:%s\n", argument->file_name);
#endif

    pthread_mutex_lock(&fp_mutex);
    fp = fopen(argument->file_name, "r");
    if(fp == NULL){
        perror("run_sender(): ");
        clean_exit();
    }

    fseek(fp, 0, SEEK_END);
    int file_size = ftell(fp);
    char * buf = (char *)malloc(file_size+1);
    memset(buf, 0, file_size);
    rewind(fp);

    if((fread(buf, sizeof(char), file_size, fp)) !=  file_size){
        perror("fread error!\n");
    }
    fclose(fp);
    pthread_mutex_unlock(&fp_mutex);

    int res = incp_send(argument->conn_id, buf, file_size, argument->src_ip, argument->dst_ip);
    if(res < 0){
        printf("send error!\n");
    }else{
        printf("sender end\n");
    }
}
