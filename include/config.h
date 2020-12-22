#ifndef CONFIG_H
#define CONFIG_H

#define DRIVER_IF_NAME "enp0s3" //使用的物理网卡名称
#define DRIVER_IF_IP      \
    {                     \
        10, 0, 2, 15 \
    } //自定义网卡ip地址
#define DRIVER_IF_MAC                      \
    {                                      \
        0x08,0x00,0x27,0x02,0xa5,0xe3 \
    }                     //自定义网卡mac地址

#define Boardcast_MAC \
    {                               \
        0xff,0xff,0xff,0xff,0xff,0xff\
    }

#define ETHERNET_MTU 1500 //以太网最大传输单元

#define ARP_MAX_ENTRY 16       //arp表最大长度
#define ARP_TIMEOUT_SEC 60 * 5 //arp表过期时间
#define ARP_MIN_INTERVAL 1     //向相同地址发送arp请求的最小间隔

#define IP_DEFALUT_TTL 64 //IP默认TTL

#define UDP_MAX_HANDLER 16 //最多的UDP处理程序数

#endif