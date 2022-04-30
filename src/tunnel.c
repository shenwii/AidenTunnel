#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/fcntl.h>
#include <sys/random.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>

#include "tun.h"
#include "log.h"
#include "crc32.h"
#include "common.h"

//don't change this
#define TUN_MTU 1420
#define ICMP_BUFFER_LENGTH 1500
#define EPOLL_NUM 3
#define IO_MUXING_TIMEOUT 5000
#define HEARTBEAT_SNEDTIME 10
#define HEARTBEAT_TIMEOUT 30

#define TUNNEL_TPYE_HEARTBEAT 0x01
#define TUNNEL_TPYE_FORWARD 0x02

typedef struct
{
    //package type, 1:TUNNEL_TPYE_HEARTBEAT, 2:TUNNEL_TPYE_FORWARD
    unsigned char type;
    unsigned char unused[1];
    //source ether mac addresss
    struct ether_addr seth;
    //key crc32
    union
    {
        unsigned char crc32[4];
        uint32_t crc32_i;
    } key_u;
    //source address
    struct in_addr saddr;
} __attribute__((__packed__)) tunnel_hdr_t;

typedef struct raw_socket_s raw_socket_t;

struct raw_socket_s
{
    //socket fd
    int fd;
    //tun address
    struct in_addr addr;
    //tun mac address
    struct ether_addr ether_addr;
    //client address
    struct sockaddr_storage client_addr;
    //icmp code
    uint16_t code;
    //icmp sed, each time the client sends an icmp packet, seq needs to add 1
    uint16_t seq;
    //time of last heartbeat
    time_t heartbeat_time;
    struct raw_socket_s *next;
};

static void __usage(char *prog, struct option *long_options, size_t len)
{
    char option_str[25];
    fprintf(stderr, "Usage: %s [OPTION]...\n", prog);
    fprintf(stderr, "Option:\n");
    for(int i = 0; i < len; i++) {
        sprintf(option_str, "  -%c, --%s", long_options[i].val, long_options[i].name);
        fprintf(stderr, "%-24s", option_str);
        switch(long_options[i].val)
        {
            case 'a':
                fprintf(stderr, "tun device ipv4 address\n");
                break;
            case 'h':
                fprintf(stderr, "display this help and exit\n");
                break;
            case 'k':
                fprintf(stderr, "authentication key\n");
                break;
            case 'n':
                fprintf(stderr, "tun device netmask, default: 255.255.255.0\n");
                break;
            case 's':
                fprintf(stderr, "server address, runs in service mode if not specified\n");
                break;
        }
    }
    fflush(stderr);
}

static char *address_str4(struct in_addr *in_addr)
{
    static char addr[16];
    inet_ntop(AF_INET, in_addr, addr, 16);
    return addr;
}

static uint16_t __check_sum(unsigned char *data, int len) {
    register long sum = 0;
    while(len > 1) {
        sum += *data << 8 | *(data + 1);
        data += 2;
        len -= 2;
    }
    if(len)
        sum += *data << 8;
    while(sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

static void __send_icmp4(raw_socket_t *raw_socket, char type, struct sockaddr_in *addr, char *buf, size_t len)
{
    //send ipv4 icmp package
    char icmp_buffer[ICMP_BUFFER_LENGTH];
    struct icmphdr hdr;
    hdr.type = type == 0? ICMP_ECHO: ICMP_ECHOREPLY;
    hdr.code = 0;
    hdr.checksum = 0;
    hdr.un.echo.id = raw_socket->code;
    hdr.un.echo.sequence = raw_socket->seq;
    memcpy(icmp_buffer, &hdr, sizeof(struct icmphdr));
    memcpy(icmp_buffer + sizeof(struct icmphdr), buf, len);
    hdr.checksum = htons(__check_sum((unsigned char *) icmp_buffer , sizeof(struct icmphdr) + len));
    memcpy(icmp_buffer, &hdr, sizeof(struct icmphdr));
    sendto(raw_socket->fd, icmp_buffer, sizeof(struct icmphdr) + len, MSG_NOSIGNAL, (struct sockaddr*) addr, sizeof(struct sockaddr_in));
}

static void __send_icmp6(raw_socket_t *raw_socket, char type, struct sockaddr_in6 *addr, char *buf, size_t len)
{
    //send ipv6 icmp package
    char icmp_buffer[ICMP_BUFFER_LENGTH];
    struct icmp6_hdr hdr;
    hdr.icmp6_type = type == 0? ICMP6_ECHO_REQUEST: ICMP6_ECHO_REPLY;
    hdr.icmp6_code = 0;
    hdr.icmp6_cksum = 0;
    hdr.icmp6_id = raw_socket->code;
    hdr.icmp6_seq = raw_socket->seq;
    memcpy(icmp_buffer, &hdr, sizeof(struct icmp6_hdr));
    memcpy(icmp_buffer + sizeof(struct icmp6_hdr), buf, len);
    hdr.icmp6_cksum = htons(__check_sum((unsigned char *) icmp_buffer , sizeof(struct icmp6_hdr) + len));
    memcpy(icmp_buffer, &hdr, sizeof(struct icmp6_hdr));
    sendto(raw_socket->fd, icmp_buffer, sizeof(struct icmp6_hdr) + len, MSG_NOSIGNAL, (struct sockaddr*) addr, sizeof(struct sockaddr_in6));
}

static void __send_icmp(raw_socket_t *raw_socket, char type, struct sockaddr *addr, char *buf, size_t len)
{
    //send icmp package to address
    if(addr->sa_family == AF_INET6)
        __send_icmp6(raw_socket, type, (struct sockaddr_in6 *) addr, buf, len);
    else
        __send_icmp4(raw_socket, type, (struct sockaddr_in *) addr, buf, len);
}

static void __send_heartbeat(raw_socket_t *raw_socket, uint32_t key, struct sockaddr *server_addr)
{
    //send heartbeat package
    tunnel_hdr_t tunnel_hdr;
    tunnel_hdr.type = TUNNEL_TPYE_HEARTBEAT;
    tunnel_hdr.saddr = raw_socket->addr;
    tunnel_hdr.seth = raw_socket->ether_addr;
    memcpy(&tunnel_hdr.saddr, &raw_socket->addr, sizeof(tunnel_hdr.saddr));
    tunnel_hdr.key_u.crc32_i = htonl(key);
    __send_icmp(raw_socket, 0, server_addr, (char *) &tunnel_hdr, sizeof(tunnel_hdr_t));
}

/**
 * tun_fd: tun device fd
 * ip4_addr: tun device ipv4 address
 * ip4_netmask: tun device ipv4 netmask
 * key: authentication key
 * server_mode: is it a service model: 1:yes, 0:no
 * server_addr: server address
*/
static void __epoll_loop(int tun_fd, struct in_addr *ip4_addr, struct in_addr *ip4_netmask, struct ether_addr *eth_addr, char *key , char server_mode, struct sockaddr *server_addr)
{
    //buffer for data when reading tun devices
    char tun_buffer[TUN_MTU];
    //buffer for data when reading from icmp
    char icmp_buffer[ICMP_BUFFER_LENGTH];
    //epoll fd
    int epfd;
    //temporary epoll event
    struct epoll_event ev;
    //temporary epoll event array
    struct epoll_event events[EPOLL_NUM];
    //epoll wait count
    int wait_count;
    //client list
    raw_socket_t *raw_socket_list = NULL;
    //used only on the client side to store client information
    raw_socket_t raw_socket;
    //key buffer
    unsigned char key_buffer[64] = {0};
    memcpy(key_buffer, key, strlen(key));
    //calculate the key crc32
    uint32_t key_crc32 = CRC32(key_buffer, 64); 
    epfd = epoll_create1(0);
    if(epfd < 0)
    {
        LOG_ERR("create epoll failed\n");
        abort();
    }
    ev.data.ptr = NULL;
    ev.events = EPOLLIN;
    ev.data.fd = tun_fd;
    epoll_ctl(epfd, EPOLL_CTL_ADD, tun_fd, &ev);
    if(server_mode == 1)
    {
        int raw_fd4;
        int raw_fd6;
        //create ipv4 and ipv6 socket to handle icmp package
        raw_fd4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if(raw_fd4 <= 0)
        {
            LOG_ERR("create socket failed\n");
            abort();
        }
        ev.data.fd = raw_fd4;
        epoll_ctl(epfd, EPOLL_CTL_ADD, raw_fd4, &ev);

        raw_fd6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if(raw_fd6 <= 0)
        {
            LOG_ERR("create socket failed\n");
            abort();
        }
        ev.data.fd = raw_fd6;
        epoll_ctl(epfd, EPOLL_CTL_ADD, raw_fd6, &ev);
    }
    else
    {
        //create a socket to send icmp package to server
        raw_socket.fd = socket(server_addr->sa_family, SOCK_RAW, IPPROTO_ICMP);
        if(raw_socket.fd <= 0)
        {
            LOG_ERR("create socket failed\n");
            abort();
        }
        ev.data.fd = raw_socket.fd;
        epoll_ctl(epfd, EPOLL_CTL_ADD, raw_socket.fd, &ev);
        raw_socket.heartbeat_time = time(NULL);
        raw_socket.seq = 1;
        raw_socket.addr = *ip4_addr;
        raw_socket.ether_addr = *eth_addr;
        getrandom(&raw_socket.code, sizeof(raw_socket.code), GRND_RANDOM);
        __send_heartbeat(&raw_socket, key_crc32, server_addr);
    }
    while(1)
    {
        wait_count = epoll_wait(epfd, events, EPOLL_NUM, IO_MUXING_TIMEOUT);
        /*
            detecting heartbeat
            the client will send a heartbeat packet at regular intervals
            the server needs to always check if the heartbeat packet times out, and if it does, the client is considered disconnected
        */
        if(server_mode == 1)
        {
            //check if client is timeout
            raw_socket_t *pre_raw_socket = NULL;
            raw_socket_t *tmp_raw_socket;
            tmp_raw_socket = raw_socket_list;
            while(tmp_raw_socket != NULL)
            {
                if(difftime(time(NULL), tmp_raw_socket->heartbeat_time) > HEARTBEAT_TIMEOUT)
                {
                    LOG_INFO("client closed, id = %u\n", tmp_raw_socket->code);
                    if(pre_raw_socket == NULL)
                    {
                        raw_socket_list = tmp_raw_socket->next;
                        free(tmp_raw_socket);
                        tmp_raw_socket = raw_socket_list;
                    }
                    else
                    {
                        pre_raw_socket->next = tmp_raw_socket->next;
                        free(tmp_raw_socket);
                        tmp_raw_socket = pre_raw_socket->next;
                    }
                    continue;
                }
                pre_raw_socket = tmp_raw_socket;
                tmp_raw_socket = tmp_raw_socket->next;
            }
        }
        else
        {
            //check if need send heartbeat package
            if(difftime(time(NULL), raw_socket.heartbeat_time) > HEARTBEAT_SNEDTIME)
            {
                raw_socket.seq++;
                LOG_DEBUG("send heartbeat, id = %u\n", raw_socket.code);
                __send_heartbeat(&raw_socket, key_crc32, server_addr);
                raw_socket.heartbeat_time = time(NULL);
            }
        }
        for(int i = 0; i < wait_count; i++)
        {
            //events although there is still the possibility of EPOLLERR and EPOLLHUP, it should not be possible here.
            if(!(events[i].events & EPOLLIN))
                continue;
            if(events[i].data.fd == tun_fd)
            {
                //package from tun device
                int r = read(events[i].data.fd, tun_buffer, TUN_MTU);
                if(r <= sizeof(struct ether_header))
                    continue;
                struct ether_header *eth_hdr = (struct ether_header *) tun_buffer;
                if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
                {
                    struct iphdr *iphdr = (struct iphdr *) (tun_buffer + sizeof(struct ether_header));
                    //tun device, only ipv4 packets are processed, ipv6 packets are discarded
                    if(iphdr->version != 4)
                    {
                        LOG_INFO("ip version %d is not supported\n", iphdr->version);
                        continue;
                    }
                    if(server_mode == 0)
                    {
                        /*
                            if it is a client, the tun packet is forwarded to the server
                            TODO: need to optimize client routing tables
                        */
                        LOG_DEBUG("send tun package to server\n");
                        char buf[sizeof(tunnel_hdr_t) + r];
                        tunnel_hdr_t tunnel_hdr;
                        tunnel_hdr.saddr.s_addr = iphdr->saddr;
                        memcpy(&tunnel_hdr.seth, eth_hdr->ether_shost, sizeof(struct ether_addr));
                        tunnel_hdr.type = TUNNEL_TPYE_FORWARD;
                        tunnel_hdr.key_u.crc32_i = htonl(key_crc32);
                        memcpy(buf, &tunnel_hdr, sizeof(tunnel_hdr_t));
                        memcpy(buf + sizeof(tunnel_hdr_t), tun_buffer, r);
                        __send_icmp(&raw_socket, 0, server_addr, buf, sizeof(tunnel_hdr_t) + r);
                    }
                    else
                    {
                        //if it is the server side, then first determine whether the destination IP is the same virtual LAN
                        if((iphdr->daddr & ip4_netmask->s_addr) == (ip4_addr->s_addr & ip4_netmask->s_addr))
                        {
                            //if it is on the same LAN, look up the client in the routing table and forward it if found
                            raw_socket_t *tmp_raw_socket;
                            char has_client = 0;
                            for(tmp_raw_socket = raw_socket_list; tmp_raw_socket != NULL; tmp_raw_socket = tmp_raw_socket->next)
                            {
                                if(tmp_raw_socket->addr.s_addr == iphdr->daddr)
                                {
                                    LOG_INFO("send package to %s\n", address_str4((struct in_addr *) &iphdr->daddr));
                                    char buf[sizeof(tunnel_hdr_t) + r];
                                    tunnel_hdr_t tunnel_hdr;
                                    tunnel_hdr.saddr = tmp_raw_socket->addr;
                                    tunnel_hdr.seth = tmp_raw_socket->ether_addr;
                                    tunnel_hdr.key_u.crc32_i = htonl(key_crc32);
                                    tunnel_hdr.type = TUNNEL_TPYE_FORWARD;
                                    memcpy(buf, &tunnel_hdr, sizeof(tunnel_hdr_t));
                                    memcpy(buf + sizeof(tunnel_hdr_t), tun_buffer, r);
                                    __send_icmp(tmp_raw_socket, 1, (struct sockaddr *) &tmp_raw_socket->client_addr, buf, sizeof(tunnel_hdr_t) + r);
                                    has_client = 1;
                                    break;
                                }
                            }
                            if(!has_client)
                            {
                                //if the client is not found, it is discarded
                                LOG_INFO("client %s is not exists\n", address_str4((struct in_addr *) &iphdr->daddr));
                            }
                        }
                        else
                        {
                            //if it is not from the same LAN, it is discarded
                            LOG_DEBUG("not the same lan package, droped\n");
                        }
                    }
                }
                else if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IPV6)
                {
                    LOG_INFO("ipv6 not supported\n");
                }
                else if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
                {
                    struct ether_arp *eth_arp;
                    eth_arp = (struct ether_arp *) (tun_buffer + sizeof(struct ether_header));

                    if(server_mode == 0)
                    {
                        /*
                            if it is a client, the tun packet is forwarded to the server
                            TODO: need to optimize client routing tables
                        */
                        LOG_DEBUG("send tun package to server\n");
                        char buf[sizeof(tunnel_hdr_t) + r];
                        tunnel_hdr_t tunnel_hdr;
                        //tunnel_hdr.saddr.s_addr = iphdr->saddr;
                        memcpy(&tunnel_hdr.seth, eth_hdr->ether_shost, sizeof(struct ether_addr));
                        tunnel_hdr.type = TUNNEL_TPYE_FORWARD;
                        tunnel_hdr.key_u.crc32_i = htonl(key_crc32);
                        memcpy(buf, &tunnel_hdr, sizeof(tunnel_hdr_t));
                        memcpy(buf + sizeof(tunnel_hdr_t), tun_buffer, r);
                        __send_icmp(&raw_socket, 0, server_addr, buf, sizeof(tunnel_hdr_t) + r);
                    }
                    else
                    {
                        raw_socket_t *tmp_raw_socket;
                        for(tmp_raw_socket = raw_socket_list; tmp_raw_socket != NULL; tmp_raw_socket = tmp_raw_socket->next)
                        {
                            if(memcmp(&tmp_raw_socket->addr, &eth_arp->arp_tpa, sizeof(struct in_addr)) == 0)
                            {
                                char buf[sizeof(tunnel_hdr_t) + r];
                                tunnel_hdr_t tunnel_hdr;
                                //tunnel_hdr.saddr.s_addr = iphdr->saddr;
                                memcpy(&tunnel_hdr.seth, eth_hdr->ether_shost, sizeof(struct ether_addr));
                                tunnel_hdr.saddr = *ip4_addr;
                                tunnel_hdr.seth = *eth_addr;
                                tunnel_hdr.key_u.crc32_i = htonl(key_crc32);
                                tunnel_hdr.type = TUNNEL_TPYE_FORWARD;
                                memcpy(buf, &tunnel_hdr, sizeof(tunnel_hdr_t));
                                memcpy(buf + sizeof(tunnel_hdr_t), tun_buffer, r);
                                __send_icmp(tmp_raw_socket, 1, (struct sockaddr *) &tmp_raw_socket->client_addr, buf, sizeof(tunnel_hdr_t) + r);
                            }
                        }
                    }
                }
                else
                {
                    LOG_WARN("ether type 0x%04x is not supported\n", eth_hdr->ether_type);
                }
            }
            else
            {
                //package from icmp socket
                struct sockaddr_storage client_addr;
                socklen_t addr_len = sizeof(client_addr);
                int r = recvfrom(events[i].data.fd, icmp_buffer, ICMP_BUFFER_LENGTH, MSG_NOSIGNAL, (struct sockaddr *) &client_addr, &addr_len);
                tunnel_hdr_t *tunnel_hdr;
                uint16_t code;
                uint16_t seq;
                char *tmp_buf;
                size_t tmp_len;
                if(r < sizeof(struct iphdr))
                    continue;
                //the icmp packets received here start with the ip protocol, so first, the ip protocol version is parsed
                if(((struct iphdr *) icmp_buffer)->version == 4)
                {
                    //from ipv4 icmp package
                    if(r < sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(tunnel_hdr_t))
                        continue;
                    struct icmphdr *icmphdr = (struct icmphdr *) (icmp_buffer + sizeof(struct iphdr));
                    //the server side only processes packets for echo, the client side only processes packets for echo reply
                    if(server_mode == 1)
                    {
                        if(icmphdr->type != ICMP_ECHO)
                            continue;
                    }
                    else
                    {
                        if(icmphdr->type != ICMP_ECHOREPLY)
                            continue;
                    }
                    code = icmphdr->un.echo.id;
                    seq = icmphdr->un.echo.sequence;
                    tmp_buf = icmp_buffer + sizeof(struct iphdr) + sizeof(struct icmphdr);
                    tmp_len = r - sizeof(struct iphdr) - sizeof(struct icmphdr);
                }
                else if(((struct iphdr *) icmp_buffer)->version == 6)
                {
                    //from ipv6 icmp package
                    if(r < sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr) + sizeof(tunnel_hdr_t))
                        continue;
                    struct icmp6_hdr *icmphdr = (struct icmp6_hdr *) (icmp_buffer + sizeof(struct iphdr));
                    //the server side only processes packets for echo, the client side only processes packets for echo reply
                    if(server_mode == 1)
                    {
                        if(icmphdr->icmp6_type != ICMP6_ECHO_REQUEST)
                            continue;
                    }
                    else
                    {
                        if(icmphdr->icmp6_type != ICMP6_ECHO_REPLY)
                            continue;
                    }
                    code = icmphdr->icmp6_id;
                    seq = icmphdr->icmp6_seq;
                    tmp_buf = icmp_buffer + sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
                    tmp_len = r - sizeof(struct ip6_hdr) + sizeof(struct icmp6_hdr);
                }
                else
                {
                    LOG_DEBUG("unsupported ip version = %d\n", ((struct iphdr *) icmp_buffer)->version);
                    continue;
                }
                if(tmp_len < sizeof(tunnel_hdr_t))
                    continue;
                tunnel_hdr = (tunnel_hdr_t *) tmp_buf;
                tmp_buf += sizeof(tunnel_hdr_t);
                tmp_len -= sizeof(tunnel_hdr_t);
                //verify key
                if(ntohl(tunnel_hdr->key_u.crc32_i) != key_crc32)
                {
                    LOG_DEBUG("incorrect key\n");
                    continue;
                }
                switch (tunnel_hdr->type)
                {
                    case TUNNEL_TPYE_HEARTBEAT:
                        //handling heartbeat packets
                        LOG_DEBUG("recv heartbeat package\n");
                        /*
                            heartbeat packets are currently only sent from the client to the server, so if it's not the server, skip processing here
                            TODO: in the future, it can be designed so that the client sends a heartbeat packet, and the server returns the heartbeat packet with routing information together
                        */
                        if(server_mode == 0)
                            continue;
                        raw_socket_t *tmp_raw_socket;
                        raw_socket_t *last_socket = NULL;
                        char has_client = 0;
                        /*
                            find the client
                            if found, update the client information
                            if not found, add the client information
                        */
                        for(tmp_raw_socket = raw_socket_list; tmp_raw_socket != NULL; tmp_raw_socket = tmp_raw_socket->next)
                        {
                            //if has same code(id), update info
                            if(tmp_raw_socket->code == code)
                            {
                                tmp_raw_socket->addr = tunnel_hdr->saddr;
                                tmp_raw_socket->ether_addr = tunnel_hdr->seth;
                                tmp_raw_socket->seq = seq;
                                tmp_raw_socket->heartbeat_time = time(NULL);
                                tmp_raw_socket->client_addr = client_addr;
                                tmp_raw_socket->fd = events[i].data.fd;
                                has_client = 1;
                                break;
                            }
                            last_socket = tmp_raw_socket;
                        }
                        if(!has_client)
                        {
                            //if client not exists, create it
                            tmp_raw_socket = malloc(sizeof(raw_socket_t));
                            if(tmp_raw_socket == NULL)
                            {
                                LOG_ERR("malloc failed\n");
                                abort();
                            }
                            LOG_INFO("new client connected, id = %u\n", code);
                            tmp_raw_socket->addr = tunnel_hdr->saddr;
                            tmp_raw_socket->ether_addr = tunnel_hdr->seth;
                            tmp_raw_socket->heartbeat_time = time(NULL);
                            tmp_raw_socket->code = code;
                            tmp_raw_socket->seq = seq;
                            tmp_raw_socket->client_addr = client_addr;
                            tmp_raw_socket->next = NULL;
                            tmp_raw_socket->fd = events[i].data.fd;
                            if(raw_socket_list == NULL)
                            {
                                raw_socket_list = tmp_raw_socket;
                            }
                            else
                            {
                                last_socket->next = tmp_raw_socket;
                            }
                        }

                        break;
                    case TUNNEL_TPYE_FORWARD:
                        //handling forward packets
                        if(tmp_len < sizeof(struct ether_header))
                            continue;
                        struct ether_header *eth_hdr = (struct ether_header *) tmp_buf;
                        // struct ether_addr *seth;
                        // struct ether_addr *deth;
                        char *forward_buf = tmp_buf;
                        size_t forward_buf_len = tmp_len;
                        tmp_buf += sizeof(struct ether_header);
                        tmp_len -= sizeof(struct ether_header);
                        // seth = (struct ether_addr *) &eth_hdr->ether_shost;
                        // deth = (struct ether_addr *) &eth_hdr->ether_dhost;
                        if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP)
                        {
                            // struct in_addr *saddr;
                            struct in_addr *daddr;
                            if(tmp_len < sizeof(struct iphdr))
                                continue;
                            struct iphdr *ip_hdr = (struct iphdr *) tmp_buf;
                            tmp_buf += sizeof(struct iphdr);
                            tmp_len -= sizeof(struct iphdr);
                            if(ip_hdr->version != 4)
                                continue;
                            // saddr = (struct in_addr *) &ip_hdr->saddr;
                            daddr = (struct in_addr *) &ip_hdr->daddr;
                            //if the destination IP is the ip of tun, then forward
                            if(ip4_addr->s_addr == daddr->s_addr)
                            {
                                LOG_INFO("send forward package to tun\n");
                                write(tun_fd, forward_buf, forward_buf_len);
                                continue;
                            }
                            if(server_mode == 1)
                            {
                                /*
                                    if it is a server side
                                    then look for the client, and forward it to the corresponding client directly if found
                                    if the client is not found, it will be forwarded to the tun device and the kernel will handle it
                                */
                                raw_socket_t *tmp_raw_socket;
                                for(tmp_raw_socket = raw_socket_list; tmp_raw_socket != NULL; tmp_raw_socket = tmp_raw_socket->next)
                                {
                                    if(tmp_raw_socket->addr.s_addr == daddr->s_addr)
                                    {
                                        LOG_INFO("send package to %s\n", address_str4(daddr));
                                        has_client = 1;
                                        __send_icmp(tmp_raw_socket, 1, (struct sockaddr *) &tmp_raw_socket->client_addr, forward_buf - sizeof(tunnel_hdr_t), forward_buf_len + sizeof(tunnel_hdr_t));
                                        break;
                                    }
                                }
                            }
                        }
                        else if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IPV6)
                        {
                            LOG_DEBUG("unsupported ipv6 package\n");
                            continue;
                        }
                        else if(ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
                        {
                            struct ether_arp *eth_arp;
                            if(tmp_len < sizeof(struct ether_arp))
                                continue;
                            eth_arp = (struct ether_arp *) tmp_buf;
                            if(memcmp(ip4_addr, &eth_arp->arp_tpa, sizeof(struct in_addr)) == 0)
                            {
                                write(tun_fd, tmp_buf - sizeof(struct ether_header), tmp_len + sizeof(struct ether_header));
                            }
                            else
                            {
                                if(server_mode == 1)
                                {
                                    raw_socket_t *tmp_raw_socket;
                                    for(tmp_raw_socket = raw_socket_list; tmp_raw_socket != NULL; tmp_raw_socket = tmp_raw_socket->next)
                                    {
                                        if(memcmp(&tmp_raw_socket->addr, &eth_arp->arp_tpa, sizeof(struct in_addr)) == 0)
                                            __send_icmp(tmp_raw_socket, 1, (struct sockaddr *) &tmp_raw_socket->client_addr, tmp_buf - sizeof(struct ether_header) - sizeof(tunnel_hdr_t), tmp_len + sizeof(struct ether_header) + sizeof(tunnel_hdr_t));
                                    }
                                }
                            }
                        }
                        else
                        {
                            LOG_WARN("ether type 0x%04x is not supported\n", eth_hdr->ether_type);
                        }
                        break;
                    default:
                        LOG_DEBUG("unknown type = %d\n", tunnel_hdr->type);
                        break;
                }
            }

        }
    }
}

int main(int argc, char **argv)
{
    int c;
    int index;
    int tun_fd;
    struct option long_options[] = 
    {
        {"addr", required_argument, NULL, 'a'},
        {"help", no_argument, NULL, 'h'},
        {"key", required_argument, NULL, 'k'},
        {"netmask", required_argument, NULL, 'n'},
        {"server", required_argument, NULL, 's'}
    };
    char address[16] = {0};
    char key[65] = {0};
    char netmask[16] = {0};
    char server[256] = {0};
    char server_mode = 0;
    struct in_addr ip4_addr;
    struct in_addr ip4_netmask;
    struct ether_addr eth_addr;
    struct sockaddr server_addr;

    while(EOF != (c = getopt_long(argc, argv, "a:hk:n:s:", long_options, &index)))
    {
        switch(c)
        {
            case 'a':
                if(strlen(optarg) >= 16)
                {
                    fprintf(stderr, "illegal IPv4 addresses\n");
                    return 1;
                }
                memcpy(address, optarg, strlen(optarg) + 1);
                break;
            case 'h':
                __usage(argv[0], long_options, sizeof(long_options) / sizeof(struct option));
                return 1;
            case 'k':
                if(strlen(optarg) >= 64)
                {
                    fprintf(stderr, "the key is up to 64 bits\n");
                    return 1;
                }
                memcpy(key, optarg, strlen(optarg) + 1);
                break;
            case 'n':
                if(strlen(optarg) >= 16)
                {
                    fprintf(stderr, "illegal netmask addresses\n");
                    return 1;
                }
                memcpy(netmask, optarg, strlen(optarg) + 1);
                break;
            case 's':
                if(strlen(optarg) >= 256)
                {
                    fprintf(stderr, "server address is up to 256 bits\n");
                    return 1;
                }
                memcpy(server, optarg, strlen(optarg) + 1);
                break;
            case '?':
                fprintf(stderr, "unknow option:%c\n", optopt);
                __usage(argv[0], long_options, sizeof(long_options) / sizeof(struct option));
                return 1;
            default:
                break;
        }   
    }
    if(strlen(address) == 0)
    {
        fprintf(stderr, "ipv4 address cannot be empty\n");
        __usage(argv[0], long_options, sizeof(long_options) / sizeof(struct option));
        return 1;
    }
    if(strlen(key) == 0)
    {
        fprintf(stderr, "key cannot be empty\n");
        __usage(argv[0], long_options, sizeof(long_options) / sizeof(struct option));
        return 1;
    }
    if(strlen(netmask) == 0)
    {
        memcpy(netmask, "255.255.255.0", 14);
    }
    if(strlen(server) == 0)
    {
        server_mode = 1;
    }
    else
    {
        if(getfirsthostbyname(server, &server_addr) != 0)
        {
            fprintf(stderr, "can't resolve server address: %s\n", server);
            return 1;
        }
    }
    if(inet_pton(AF_INET, address, &ip4_addr) < 0)
    {
        fprintf(stderr, "illegal IPv4 addresses\n");
        return 1;
    }
    if(inet_pton(AF_INET, netmask, &ip4_netmask) < 0)
    {
        fprintf(stderr, "illegal netmask addresses\n");
        return 1;
    }
    tun_fd = tun_alloc(&ip4_addr, &ip4_netmask, &eth_addr, TUN_MTU);
    if(tun_fd < 0)
    {
        LOG_ERR("create tun device failed, you should probably run it with root\n");
        return 1;
    }
    __epoll_loop(tun_fd, &ip4_addr, &ip4_netmask, &eth_addr, key, server_mode, &server_addr);
    return 0;
}
