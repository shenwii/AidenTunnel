#ifndef _TUN_H
#define _TUN_H

#include <netinet/in.h>
#include <netinet/ether.h>

/*
    create a tun device
    only support IPv4
*/
int tun_alloc(struct in_addr *ip4_addr, struct in_addr *ip4_netmask, struct ether_addr *eth_addr, int mtu);

#endif
