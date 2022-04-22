#include "common.h"

#include <stddef.h>
#include <string.h>
#include <netdb.h>

static struct addrinfo *__gethostbyname(__const__ char *hostname)
{
    struct addrinfo *result = NULL;
    if(getaddrinfo(hostname, NULL, NULL, &result) != 0)
        return NULL;
    return result;
}

int getfirsthostbyname(__const__ char *hostname, struct sockaddr *addr)
{
    struct addrinfo *result = __gethostbyname(hostname);
    if(result == NULL)
        return 1;
    if(result->ai_family == AF_INET)
    {
        memcpy(addr, result->ai_addr, sizeof(struct sockaddr_in));
    }
    if(result->ai_family == AF_INET6)
    {
        memcpy(addr, result->ai_addr, sizeof(struct sockaddr_in6));
    }
    freeaddrinfo(result);
    return 0;
}
