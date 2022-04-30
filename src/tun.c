#include "tun.h"

#include <net/if.h>
#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_tun.h>

static int __tun_set_mtu(int udp_fd, struct ifreq *ifr, int mtu)
{
    ifr->ifr_mtu = mtu;
    if(ioctl(udp_fd, SIOCSIFMTU, ifr) <0)
        return -1;
    return 0;
}

static int __tun_set_up(int udp_fd, struct ifreq *ifr)
{
    ifr->ifr_flags |= IFF_UP;
    if(ioctl(udp_fd, SIOCSIFFLAGS, ifr) <0)
        return -1;
    return 0;
}

static int __tun_set_ip4(int udp_fd, struct ifreq *ifr, struct in_addr *ip4_addr)
{
    ((struct sockaddr_in *) &ifr->ifr_addr)->sin_family = AF_INET;
    ((struct sockaddr_in *) &ifr->ifr_netmask)->sin_addr = *ip4_addr;
    if(ioctl(udp_fd, SIOCSIFADDR, ifr) <0)
        return -1;
    return 0;
}

static int __tun_set_netmask4(int udp_fd, struct ifreq *ifr, struct in_addr *ip4_netmask)
{
    ((struct sockaddr_in *) &ifr->ifr_netmask)->sin_family = AF_INET;
    ((struct sockaddr_in *) &ifr->ifr_netmask)->sin_addr = *ip4_netmask;
    if(ioctl(udp_fd, SIOCSIFNETMASK, ifr) <0)
        return -1;
    return 0;
}

static int __tun_get_ether_address(int udp_fd, struct ifreq *ifr, struct ether_addr *eth_addr)
{
    if(ioctl(udp_fd, SIOCGIFHWADDR, ifr) <0)
        return -1;
    memcpy(eth_addr, &ifr->ifr_hwaddr.sa_data, sizeof(struct ether_addr));
    return 0;
}

int tun_alloc(struct in_addr *ip4_addr, struct in_addr *ip4_netmask, struct ether_addr *eth_addr, int mtu)
{
    struct ifreq ifr;
    int fd;
    char *tun_dev_name = "tap%d";
    memset(&ifr, 0, sizeof(struct ifreq));
    fd = open("/dev/net/tun", O_RDWR);
    if(fd <= 0)
        return -1;
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    memcpy(ifr.ifr_name, tun_dev_name, strlen(tun_dev_name) + 1);
    if(ioctl(fd, TUNSETIFF, &ifr) < 0)
    {
        close(fd);
        return -1;
    }
    if(ioctl(fd, TUNSETPERSIST, 0) < 0)
    {
        close(fd);
        return -1;
    }
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(udp_fd <= 0)
    {
        close(fd);
        return -1;
    }
    if(__tun_set_mtu(udp_fd, &ifr, mtu) < 0)
    {
        close(udp_fd);
        close(fd);
        return -1;
    }
    if(__tun_set_ip4(udp_fd, &ifr, ip4_addr) < 0)
    {
        close(udp_fd);
        close(fd);
        return -1;
    }
    if(__tun_set_netmask4(udp_fd, &ifr, ip4_netmask) < 0)
    {
        close(udp_fd);
        close(fd);
        return -1;
    }
    if(__tun_set_up(udp_fd, &ifr) < 0)
    {
        close(udp_fd);
        close(fd);
        return -1;
    }
    if(__tun_get_ether_address(udp_fd, &ifr, eth_addr) < 0)
    {
        close(udp_fd);
        close(fd);
        return -1;
    }

    close(udp_fd);
    return fd;
}
