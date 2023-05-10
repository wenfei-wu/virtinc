#ifndef _H_ACTION_
#define _H_ACTION_

#include "util.h"

#include "defs.h"
#include "calc_math.h"

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include "osrng.h"

#include "integer.h"

#include "nbtheory.h"

#include "dh.h"

#include "secblock.h"

#include <hex.h>

#include <filters.h>

using namespace CryptoPP;

DH dh;
SecByteBlock opub(INCP_PAYLOAD);
SecByteBlock priv(INCP_PAYLOAD);
static uint8 my_key[INCP_PAYLOAD + 5];

#ifndef amin
#define amin(x, y) ((x) > (y) ? (y) : (x))
#endif
  

void sw_send(ip_pcb_t *ip, int port) {
  int length = ((ip_header_t *)ip)->length;
  ((ip_header_t *)ip)->checksum = 0;
  ((ip_header_t *)ip)->checksum = compute_checksum(ip, length);
  int ret = pcap_inject(pcap_handle_group[port - 1], ip, length);
  if(ret != length)
    perror("packet damage: ");
  send_packet_num++;
}

void sw_send_ack(ip_pcb_t *ip, int port) {
  ip_pcb_t sd;
  memcpy(&sd, ip, sizeof(ip_pcb_t));
  sd.ip_head.src_ip = (ip->ip_head).dst_ip;
  sd.ip_head.dst_ip = (ip->ip_head).src_ip;
  ((incp_header_t *)(sd.data))->flag = 1;
  ((incp_header_t *)(sd.data))->payload_length = 0;
  ((in_pcb_t *)(sd.data))->data[0] = 0;
  sd.ip_head.length = sizeof(ip_header_t) + sizeof(incp_header_t);
  sw_send(&sd, port);
}

void calc_load_send(ip_pcb_t *ip, char *data, int seq) {
  memset(ip, 0, sizeof(ip_pcb_t));
  ((incp_header_t *)(ip->data))->flag = 7;
  ((incp_header_t *)(ip->data))->seq_num = seq;
  ((incp_header_t *)(ip->data))->payload_length = INCP_PAYLOAD;
  memcpy(((in_pcb_t *)(ip->data))->data, data, INCP_PAYLOAD);
  ip->ip_head.length = sizeof(ip_header_t) + sizeof(incp_header_t) + INCP_PAYLOAD;
  sw_send(ip, 1);
}

void generate_key(uint8 *key) {
  uint8 tmp;
  for(int i = 1; i < INCP_PAYLOAD; ++i)
    my_key[i] ^= my_key[i - 1];
  for(int i = 1; i < INCP_PAYLOAD; i <<= 1)
    for(int j = 0; i + j < INCP_PAYLOAD; j += i) {
      tmp = my_key[i];
      my_key[i] += my_key[i + j];
      my_key[i + j] -= tmp;
    }
  memcpy(key, my_key, INCP_PAYLOAD);
}

void calc_pre_send(ip_pcb_t *ip, int port) {
  agg_p = 0;
  for(int i = 0; i < WINDOW_SIZE && i < total_packets; ++i) {
    memset(&agg_buffer[i], 0, sizeof(ip_pcb_t));
    ((incp_header_t *)(agg_buffer[i].data))->flag = 7;
    ((incp_header_t *)(agg_buffer[i].data))->seq_num = i;
    ((incp_header_t *)(agg_buffer[i].data))->payload_length = INCP_PAYLOAD;
    agg_buffer[i].ip_head.length = sizeof(ip_header_t) + sizeof(incp_header_t) + INCP_PAYLOAD;
    generate_key(((uint8 *)((in_pcb_t *)(ip->data))->data));
    agg_flag[i] = 3;
    agg_time[i] = clock();
    agg_port[i] = port;
    sw_send(&agg_buffer[i], port);
  }
}

int action_nop(ip_pcb_t *ip, int port) {
  printf("--> %s\n", __FUNCTION__);
  sw_send(ip, port);
  return 0;
}

int action_clear(ip_pcb_t *ip, int port) {
  printf("--> %s\n", __FUNCTION__);
  in_pcb_t *incp = (in_pcb_t *)(ip->data);
  ((incp_header_t *)incp)->payload_length = 0;
  incp->data[0] = 0;
  ((ip_header_t *)ip)->length = sizeof(ip_header_t) + sizeof(incp_header_t);
  sw_send(ip, port);
  return 0;
}

/*******************************************************
 * src --------------|       |->src---copy-|
 *                   |--xor--|             |
 * agg_buffer(calc) -|                     |->agg_buffer
 *
 * return -1: drop
 * return 0: send ACK to src
 * return x: send ACK to src
 *           send result(agg_buffer[x-1]) to next stop
 ******************************************************/
int action_aggregation_src(ip_pcb_t *ip, int port) {
  in_pcb_t *incp = (in_pcb_t *)(ip->data);
  int p = ((incp_header_t *)incp)->seq_num;
  printf("--> %s, seq_num = %d, win_front = %d\n", __FUNCTION__, p, agg_p);
  int front = agg_p;
  int back = amin(agg_p + WINDOW_SIZE, total_packets);
  if(p < front || p >= back) // out range
    return -1;
  p = p % WINDOW_SIZE;
  sw_send_ack(ip, port);
  if(agg_flag[p] & 1) // repate
    return -1;
  if(agg_flag[p] == 0) {
    agg_flag[p] = 1;
    agg_port[p] = port ^ 2;
    memcpy(&agg_buffer[p], ip, sizeof(ip_pcb_t));
    return 1;
  }
  char *data1 = incp->data;
  char *data2 = ((in_pcb_t *)(agg_buffer[p].data))->data;
  for(int i = 0; i < (incp->incp_head).payload_length; ++i)
    data1[i] ^= data2[i];
  memcpy(&agg_buffer[p], ip, sizeof(ip_pcb_t));
  agg_port[p] = port ^ 2;
  agg_time[p] = clock();
  agg_flag[p] = 3;
  sw_send(&agg_buffer[p], agg_port[p]);
  return 2;
}

int action_sw_ack(ip_pcb_t *ip, int port) {
  printf("--> %s\n", __FUNCTION__);
  in_pcb_t *incp = (in_pcb_t *)(ip->data);
  int p = ((incp_header_t *)incp)->seq_num;
  printf("--> %s, seq_num = %d\n", __FUNCTION__, p);
  int front = agg_p;
  int back = amin(agg_p + WINDOW_SIZE, total_packets);
  if(p < front || p >= back)
    return 0;
  p %= WINDOW_SIZE;  
  agg_flag[p] |= 4;
  while(agg_p != total_packets && agg_flag[agg_p % WINDOW_SIZE] == 7) {
    agg_flag[agg_p % WINDOW_SIZE] = 0;
    ++agg_p;
  }
  return -1;
}  

/*******************************************************
 * calc -------------|       |->src
 *                   |--xor--|       
 * agg_buffer(src) --|               
 *
 * return -1: drop
 * return 0: send ACK to src
 * return x: send ACK to src
 *           send result(agg_buffer[x-1]) to next stop
 ******************************************************/
int action_aggregation_calc(ip_pcb_t *ip, int port) {
  in_pcb_t *incp = (in_pcb_t *)(ip->data);
  int p = ((incp_header_t *)incp)->seq_num;
  int front = agg_p;
  int back = amin(agg_p + WINDOW_SIZE, total_packets);
  printf("--> %s, seq_num = %d, win = [%d, %d]\n", __FUNCTION__, p, agg_p, back);
  if(p < back)
    sw_send_ack(ip, port);
  if(p < front || p >= back) // out range
    return -1;
  p = p % WINDOW_SIZE;
  if(agg_flag[p] & 2) // repate
    return -1;
  if(agg_flag[p] == 0) {
    agg_flag[p] = 2;
    memcpy(&agg_buffer[p], ip, sizeof(ip_pcb_t));
    return 0;
  }
  char *data1 = incp->data;
  char *data2 = ((in_pcb_t *)(agg_buffer[p].data))->data;
  for(int i = 0; i < (incp->incp_head).payload_length; ++i)
    data2[i] ^= data1[i];
  agg_time[p] = clock();
  agg_flag[p] = 3;
  sw_send(&agg_buffer[p], agg_port[p]);
  return 2;
}

int action_calc_ack(ip_pcb_t *ip, int port) {
  char tmp[INCP_PAYLOAD];
  in_pcb_t *incp = (in_pcb_t *)(ip->data);
  int p = ((incp_header_t *)incp)->seq_num;
  int front = agg_p;
  int back = amin(agg_p + WINDOW_SIZE, total_packets);
  printf("--> %s, seq_num = %d, [%d, %d]\n", __FUNCTION__, p, front, back);
  if(p < front || p >= back)
    return -1;
  p %= WINDOW_SIZE;
  agg_flag[p] = 7;
  while(agg_p != total_packets && agg_flag[agg_p % WINDOW_SIZE] == 7) {
    agg_flag[agg_p % WINDOW_SIZE] = 0;
    if(agg_p + WINDOW_SIZE < total_packets) {
      generate_key((uint8 *)tmp);
      calc_load_send(&agg_buffer[agg_p % WINDOW_SIZE], tmp, agg_p + WINDOW_SIZE);
      agg_port[agg_p % WINDOW_SIZE] = 1;
      agg_flag[agg_p % WINDOW_SIZE] = 3;
      agg_time[agg_p % WINDOW_SIZE] = clock();
    }
    ++agg_p;
  }
  return 0;
}

// load p, g, g^a
int action_load_a(ip_pcb_t *ip, int port) {
  in_pcb_t *incp = (in_pcb_t *)(ip->data);
  total_packets = (incp->incp_head).seq_num;
  printf("--> %s, tot = %d\n", __FUNCTION__, total_packets);
  AutoSeededRandomPool rnd;
  dh.AccessGroupParameters().GenerateRandomWithKeySize(rnd, INCP_PAYLOAD * 8);
  Integer p = dh.GetGroupParameters().GetModulus();
  Integer q = dh.GetGroupParameters().GetSubgroupOrder();
  Integer g = dh.GetGroupParameters().GetGenerator();
  cout << (2 * q + 1 == p) << endl;
  cout << "p: " << std::hex << p << endl;
  cout << "g: " << std::hex << g << endl;
  priv = SecByteBlock(dh.PrivateKeyLength());
  SecByteBlock pub(dh.PublicKeyLength());
  dh.GenerateKeyPair(rnd, priv, pub);
  memset(incp->data, 0, 3 * INCP_PAYLOAD);
  p.Encode((unsigned char *)(incp->data), INCP_PAYLOAD);
  g.Encode((unsigned char *)(incp->data + INCP_PAYLOAD), INCP_PAYLOAD);
  memcpy(incp->data + 2 * INCP_PAYLOAD, pub.BytePtr(), pub.SizeInBytes());
  ((incp_header_t *)incp)->payload_length = 3 * INCP_PAYLOAD;
  ((ip_header_t *)ip)->length = sizeof(ip_header_t) + sizeof(incp_header_t) + 3 * INCP_PAYLOAD;
  sw_send(ip, port);
  return 0;
}

// load g^b;
int action_load_b(ip_pcb_t *ip, int port) {
  in_pcb_t *incp = (in_pcb_t *)(ip->data);
  printf("--> %s\n", __FUNCTION__);
  SecByteBlock pub(dh.PublicKeyLength());
  AutoSeededRandomPool rnd;
  dh.GenerateKeyPair(rnd, priv, pub);
  SecByteBlock shared(dh.AgreedValueLength());
  dh.Agree(shared, priv, opub);
  Integer t;
  t.Decode(shared.BytePtr(), shared.SizeInBytes());
  cout << "shared: " << std::hex << t << endl;
  memcpy(my_key, shared.BytePtr(), INCP_PAYLOAD);
  memcpy(incp->data, pub.BytePtr(), INCP_PAYLOAD);
  ((incp_header_t *)incp)->payload_length = INCP_PAYLOAD;
  ((ip_header_t *)ip)->length = sizeof(ip_header_t) + sizeof(incp_header_t) + INCP_PAYLOAD;
  sw_send(ip, port);
  calc_pre_send(ip, port);
  return 0;
}

int action_save_a(ip_pcb_t *ip, int port) {
  in_pcb_t *incp = (in_pcb_t *)(ip->data);
  agg_p = 0;
  total_packets = (incp->incp_head).seq_num;
  printf("--> %s, tot = %d\n", __FUNCTION__, total_packets);
  Integer p, g, q, o;
  p.Decode((unsigned char *)(incp->data), INCP_PAYLOAD);
  g.Decode((unsigned char *)(incp->data + INCP_PAYLOAD), INCP_PAYLOAD);
  o.Decode((unsigned char *)(incp->data + 2 * INCP_PAYLOAD), INCP_PAYLOAD);
  o.Encode(opub.BytePtr(), opub.SizeInBytes());
  q = (p - 1) / 2;
  dh.AccessGroupParameters().Initialize(p, q, g);
  ((incp_header_t *)incp)->payload_length = 0;
  incp->data[0] = 0;
  ((ip_header_t *)ip)->length = sizeof(ip_header_t) + sizeof(incp_header_t);
  sw_send(ip, port);
  return 0;
}

int action_generate_key(ip_pcb_t *ip, int port) {
  in_pcb_t *incp = (in_pcb_t *)(ip->data);
  printf("--> %s\n", __FUNCTION__);
  Integer o;
  o.Decode((unsigned char *)(incp->data), INCP_PAYLOAD);
  o.Encode(opub.BytePtr(), opub.SizeInBytes());
  incp->data[0] = 0;
  ((ip_header_t *)ip)->length = sizeof(ip_header_t) + sizeof(incp_header_t);
  sw_send(ip, port);
  SecByteBlock shared(dh.AgreedValueLength());
  dh.Agree(shared, priv, opub);
  Integer t;
  t.Decode(shared.BytePtr(), shared.SizeInBytes());
  cout << "shared: " << std::hex << t << endl;
  memcpy(my_key, shared.BytePtr(), INCP_PAYLOAD);
  o.Decode(shared.BytePtr(), shared.SizeInBytes());
  cout << "o: " << std::hex << o << endl;
  calc_pre_send(ip, port);
  return 0;
}

int action_save_total(ip_pcb_t *ip, int port) {
  in_pcb_t *incp = (in_pcb_t *)(ip->data);
  agg_p = 0;
  total_packets = (incp->incp_head).seq_num;
  sw_send(ip, port);
  printf("--> %s, tot = %d\n", __FUNCTION__, total_packets);
  return 0;
}

#endif // _ACTION_H_
