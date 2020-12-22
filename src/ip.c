#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "udp.h"
#include <string.h>
#include <stdio.h>

/**
 * @brief 处理一个收到的数据包
 *        你首先需要做报头检查，检查项包括：版本号、总长度、首部长度等。
 * 
 *        接着，计算头部校验和，注意：需要先把头部校验和字段缓存起来，再将校验和字段清零，
 *        调用checksum16()函数计算头部检验和，比较计算的结果与之前缓存的校验和是否一致，
 *        如果不一致，则不处理该数据报。
 * 
 *        检查收到的数据包的目的IP地址是否为本机的IP地址，只处理目的IP为本机的数据报。
 * 
 *        检查IP报头的协议字段：
 *        如果是ICMP协议，则去掉IP头部，发送给ICMP协议层处理
 *        如果是UDP协议，则去掉IP头部，发送给UDP协议层处理
 *        如果是本实验中不支持的其他协议，则需要调用icmp_unreachable()函数回送一个ICMP协议不可达的报文。
 *          
 * @param buf 要处理的包
 */
void ip_in(buf_t *buf)
{
    ip_hdr_t* head = (ip_hdr_t*)buf->data;
    if(head->hdr_len*IP_HDR_LEN_PER_BYTE !=sizeof(ip_hdr_t) ||
        head->version != IP_VERSION_4 ||
        swap16(head->total_len) > 65535 )
    {
        fprintf(stderr, "Error in ip_header\n");
        return;
    }

    uint16_t cksum = head->hdr_checksum;
    head->hdr_checksum = 0;
    if(checksum16((uint16_t*)head,sizeof(ip_hdr_t))!=(head->hdr_checksum = cksum)){
        fprintf(stderr, "Error in checkoutsum ip_header\n");
        return;
    }

    if(memcmp(head->dest_ip,net_if_ip,NET_IP_LEN)!=0){
        return;
    }
    switch(head->protocol){
        case NET_PROTOCOL_ICMP:
            buf_remove_header(buf,sizeof(ip_hdr_t));
            icmp_in(buf,head->src_ip);
            break;
        case NET_PROTOCOL_UDP:
            buf_remove_header(buf,sizeof(ip_hdr_t));
            udp_in(buf,head->src_ip);
            break;
        default:
            icmp_unreachable(buf,head->src_ip,ICMP_CODE_PROTOCOL_UNREACH);
    }
    

}

/**
 * @brief 处理一个要发送的ip分片
 *        你需要调用buf_add_header增加IP数据报头部缓存空间。
 *        填写IP数据报头部字段。
 *        将checksum字段填0，再调用checksum16()函数计算校验和，并将计算后的结果填写到checksum字段中。
 *        将封装后的IP数据报发送到arp层。
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    buf_add_header(buf,sizeof(ip_hdr_t));
    ip_hdr_t* head = (ip_hdr_t* )buf->data;
    head->hdr_len = sizeof(ip_hdr_t)/IP_HDR_LEN_PER_BYTE;
    head->version = IP_VERSION_4;
    head->tos = 0;
    head->total_len = swap16(buf->len);
    head->id = swap16(id);
    head->flags_fragment = (mf?IP_MORE_FRAGMENT: 0) | swap16(offset);
    head->ttl = IP_DEFALUT_TTL;
    head->protocol = protocol;
    head->hdr_checksum = 0;
    memcpy(head->src_ip,net_if_ip,NET_IP_LEN);
    memcpy(head->dest_ip,ip,NET_IP_LEN);
    head->hdr_checksum = checksum16((uint16_t*)head,sizeof(ip_hdr_t));
    arp_out(buf,ip,NET_PROTOCOL_IP);
}

/**
 * @brief 处理一个要发送的ip数据包
 *        你首先需要检查需要发送的IP数据报是否大于以太网帧的最大包长（1500字节 - 以太网报头长度）。
 *        
 *        如果超过，则需要分片发送。 
 *        分片步骤：
 *        （1）调用buf_init()函数初始化buf，长度为以太网帧的最大包长（1500字节 - 以太网报头长度）
 *        （2）将数据报截断，每个截断后的包长度 = 以太网帧的最大包长，调用ip_fragment_out()函数发送出去
 *        （3）如果截断后最后的一个分片小于或等于以太网帧的最大包长，
 *             调用buf_init()函数初始化buf，长度为该分片大小，再调用ip_fragment_out()函数发送出去
 *             注意：id为IP数据报的分片标识，从0开始编号，每增加一个分片，自加1。最后一个分片的MF = 0
 *    
 *        如果没有超过以太网帧的最大包长，则直接调用调用ip_fragment_out()函数发送出去。
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    static uint16_t id =0;
    if(buf->len>ETHERNET_MTU-sizeof(ip_hdr_t)){
        uint16_t len = buf->len;
        uint16_t offset = 0;
        while(len>ETHERNET_MTU-sizeof(ip_hdr_t)){
            buf_t ip_buf;
            buf_copy(&ip_buf,buf);
            buf->len = ETHERNET_MTU-sizeof(ip_hdr_t);
            buf->data += offset?ETHERNET_MTU:0;
            ip_fragment_out(buf,ip,protocol,id,offset?offset*(ETHERNET_MTU-sizeof(ip_hdr_t))>>3:0,1);
            len -= ETHERNET_MTU-sizeof(ip_hdr_t);
            offset++;
        }
        buf->data += offset?ETHERNET_MTU:0;
        buf->len = len;
        ip_fragment_out(buf,ip,protocol,id,offset*(ETHERNET_MTU-sizeof(ip_hdr_t))>>3,0);
    }
    else
    {
        ip_fragment_out(buf,ip,protocol,id,0,0);
    }
    id++;
    
}
