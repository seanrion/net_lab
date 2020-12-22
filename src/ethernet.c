#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
#include <string.h>
#include <stdio.h>

/**
 * @brief 处理一个收到的数据包
 *        你需要判断以太网数据帧的协议类型，注意大小端转换
 *        如果是ARP协议数据包，则去掉以太网包头，发送到arp层处理arp_in()
 *        如果是IP协议数据包，则去掉以太网包头，发送到IP层处理ip_in()
 * 
 * @param buf 要处理的数据包
 */

void swap_endian(buf_t* buf){
    short* h = (short*)buf->data;
    uint16_t i;
    for(i=0;i<buf->len;i+=2){
        *h = swap16(*h);
        h++;
    }
}

void ethernet_in(buf_t *buf)
{
    ether_hdr_t* head = (ether_hdr_t*)buf->data;
    if(head->protocol==swap16(NET_PROTOCOL_ARP)){
        buf_remove_header(buf, sizeof(ether_hdr_t));
        arp_in(buf);
    }

    if(head->protocol==swap16(NET_PROTOCOL_IP)){
        buf_remove_header(buf, sizeof(ether_hdr_t));
        ip_in(buf);
    }
    
}

/**
 * @brief 处理一个要发送的数据包
 *        你需添加以太网包头，填写目的MAC地址、源MAC地址、协议类型
 *        添加完成后将以太网数据帧发送到驱动层
 * 
 * @param buf 要处理的数据包
 * @param mac 目标ip地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    buf_add_header(buf,sizeof(ether_hdr_t));
    ether_hdr_t* head = (ether_hdr_t*)buf->data;
    uint8_t src[NET_MAC_LEN] = DRIVER_IF_MAC;
    uint16_t i;
    for(i=0;i<NET_MAC_LEN;i++){
        head->src[i] = src[i];
        head->dest[i] = mac[i];
    }
    head->protocol = swap16(protocol);
    driver_send(buf);
}

/**
 * @brief 初始化以太网协议
 * 
 * @return int 成功为0，失败为-1
 */
int ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MTU + sizeof(ether_hdr_t));
    return driver_open();
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0){
        //rxbuf.len -= 12;
        ethernet_in(&rxbuf);
    }
}
