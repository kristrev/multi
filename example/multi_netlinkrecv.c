#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <net/if.h>

typedef enum{
    LINK_DOWN = 0,
    LINK_UP
} link_state;

#define MAX_BUFSIZE 1500

int main(int argc, char *argv[]){
    struct sockaddr_nl src_addr, dest_addr;
    struct nlmsghdr *nlh = NULL;
    struct iovec iov;
    struct msghdr msg;
    int32_t sockfd, retval;
    uint8_t *buf;
    uint8_t devname[IFNAMSIZ];
    int32_t *ifi_idx = NULL;

    if((sockfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_GENERIC)) < 0){
        perror("Could not create netlink socket");
        exit(EXIT_FAILURE);
    }

    memset(&src_addr, 0, sizeof(src_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));

    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = 1;

    if(bind(sockfd, (struct sockaddr*) &src_addr, sizeof(src_addr)) < 0){
        perror("Could not bind netlink socket");
        exit(EXIT_FAILURE);
    }

    nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(MAX_BUFSIZE));
    memset(nlh, 0, NLMSG_SPACE(MAX_BUFSIZE));

    iov.iov_base = (void*) nlh;
    iov.iov_len = NLMSG_SPACE(MAX_BUFSIZE);
    msg.msg_name = (void *) &dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    fprintf(stderr, "Ready to receive netlink multicast messages on socket %d\n", sockfd);

    while(1){
        retval = recvmsg(sockfd, &msg, 0);
        buf = NLMSG_DATA(nlh); 

        ifi_idx = (uint32_t *) (buf+1);
        fprintf(stderr, "Index %u State %u %d\n", *ifi_idx, buf[0], retval);

        if(if_indextoname(*ifi_idx, devname) == NULL){
            printf("APP: Could not find interface name for index %u\n", *ifi_idx);
            memcpy(devname, "NULL", 5);
        }

        if(buf[0] == LINK_UP)
            printf("APP: Interface %s is up, index %u\n", devname, *ifi_idx);
        else
            printf("APP: Interface %s is down (can be wrong, not to be trusted), index %u\n", devname, buf[1]);
    }

    fprintf(stderr, "Received %d bytes\n", retval);
}
