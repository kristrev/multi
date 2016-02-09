/*
 * Copyright 2013 Kristian Evensen <kristian.evensen@gmail.com>
 *
 * This file is part of Multi Network Manager (MNM). MNM is free software: you
 * can redistribute it and/or modify it under the terms of the Lesser GNU
 * General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * MNM is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Network Device Listener. If not, see http://www.gnu.org/licenses/.
 */

#include "multi_dhcp_network.h"
#include "multi_dhcp_constants.h"
#include "multi_common.h"

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <string.h>
#include <net/if.h>
#include <linux/filter.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

/* taken from iputils which basically copied it from RFC 1071 */
static uint16_t multi_dhcp_in_cksum(const uint16_t *addr, register int len, 
        uint16_t csum){
    int nleft = len;
    const uint16_t *w = addr;
    uint16_t answer;
    int sum = csum;

    /*
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1)
        sum += htons(*(u_char *)w << 8);

    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff);     /* add hi 16 to low 16 */
    sum += (sum >> 16);                     /* add carry */
    answer = ~sum;                          /* truncate to 16 bits */
    return (answer);
}

void multi_dhcp_notify_link_module(int32_t pipe_fd){
    if(write(pipe_fd, "a", 1) < 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not notify link module\n");
    }
}

int multi_dhcp_snd_msg_raw(int sock, struct in_addr from_ip, int from_if, 
        struct multi_dhcp_message *msg, uint8_t broadcast) {
    int length =  msg->pos - &msg->op;
    uint16_t checksum;

    struct {
        struct iphdr ip;
        struct udphdr udp;
    } hdr;

    struct sockaddr_ll addr = {
        .sll_family = AF_PACKET,
        .sll_protocol = htons(ETH_P_IP),
        .sll_ifindex = from_if,
        .sll_hatype = 0,
        .sll_pkttype = 0,
        .sll_halen = ETH_ALEN
    };

    struct iovec iov[] = {
        { .iov_base = &hdr, .iov_len = sizeof(hdr) },
        { .iov_base = &msg->op, .iov_len = length }
    };

    struct msghdr msghdr = {
        .msg_name = &addr,
        .msg_namelen = sizeof(addr),
        .msg_iov = iov,
        .msg_iovlen = 2,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0
    };

    memset(addr.sll_addr, 255, ETH_ALEN); /* broadcast */

    hdr.ip.version = 4;
    hdr.ip.ihl = 5; /* minimal 20 byte header w/o options */
    hdr.ip.tos = 0;
    hdr.ip.tot_len = htons(sizeof(hdr.ip) + sizeof(hdr.udp) + length);
    hdr.ip.id = 0;
    hdr.ip.frag_off = htons(IP_DF); //Don't fragment
    hdr.ip.ttl = 64;
    hdr.ip.protocol = IPPROTO_UDP;

    if(broadcast){
        hdr.ip.saddr = from_ip.s_addr;
        hdr.ip.daddr = 0xffffffff;
    } else {
        hdr.ip.saddr = msg->ciaddr;
        hdr.ip.daddr = from_ip.s_addr;
    }

    hdr.ip.check = 0;
    hdr.ip.check = multi_dhcp_in_cksum((u_short *)&hdr.ip, 20, hdr.ip.check);

    hdr.udp.source = htons(BOOTP_CLIENT_PORT);
    hdr.udp.dest = htons(BOOTP_SERVER_PORT);
    hdr.udp.len = htons(length + sizeof(struct udphdr));
    hdr.udp.check = 0; // set to 0 for calculation

    checksum = htons(IPPROTO_UDP);
    checksum = multi_dhcp_in_cksum((u_short *)&hdr.udp.len, 2, checksum);
    checksum = multi_dhcp_in_cksum((u_short *)&hdr.ip.saddr, 16, ~checksum); 
    checksum = multi_dhcp_in_cksum((u_short *)&msg->op, length, ~checksum);

    hdr.udp.check = checksum;

    return sendmsg(sock, &msghdr, 0);
}

int multi_dhcp_snd_msg_udp(int sock, struct in_addr *to, 
        struct multi_dhcp_message *msg) {
    struct sockaddr_in toadr;
    int length = msg->pos - &msg->op;
      
    toadr.sin_family = AF_INET;
    toadr.sin_port = htons(BOOTP_SERVER_PORT);
    toadr.sin_addr = *to;
    return sendto(sock, &msg->op, length, 0, (const struct sockaddr *)&toadr, 
            sizeof(toadr));
}

int32_t multi_dhcp_recv_msg(struct multi_dhcp_info *di, 
        struct multi_dhcp_message *dhcp_msg){
    char dframe[ETH_DATA_LEN];
    struct sockaddr_ll addr;
    socklen_t addrsize = sizeof(addr);
    ssize_t plen;

    struct iphdr *iph;
    struct udphdr *udph;
    uint8_t *dhcp_payload;

    memset(dhcp_msg, 0, sizeof(*dhcp_msg));

    plen = recvfrom(di->raw_sock, dframe, sizeof(dframe), 0, 
            (struct sockaddr *)&addr, &addrsize);

    if (plen == -1) 
        return -1;

    if(ntohs(addr.sll_protocol) == ETH_P_ARP){
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Got an ARP-message\n");
        return -1;
    }

    iph = (struct iphdr *) dframe;

    if(iph->protocol != IPPROTO_UDP){
        fprintf(stderr, "Received something that is not UDP\n");
        return -1;
    }

    udph = (struct udphdr *) (iph + 1);

    /* Since I don't have an IP, port is the only thing I can check for */
    if (udph->source != htons(BOOTP_SERVER_PORT)){ 
        fprintf(stderr, "Server port is wrong.\n");
        return -1;
    }

    if (udph->dest != htons(BOOTP_CLIENT_PORT)){
        fprintf(stderr, "Client port is wrong\n");
        return -1;
    }

    dhcp_payload = (uint8_t *) (udph + 1);
    memcpy(&(dhcp_msg->op), dhcp_payload,  ntohs(udph->len) - 
            sizeof(struct udphdr));

    /* No DHCP */
    if(memcmp(&(dhcp_msg->options), multi_dhcp_vendcookie, 4)){
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Vendor cookie was not equal, this is not a" 
                "valid DHCP packet\n"); 
        return -1;
    }
   
    /* First value is casted! The reason for adding 4 is that the first four 
     * bytes of the option field is the vendor cookie  */ 
    dhcp_msg->pos = (uint8_t*) &(dhcp_msg->options) + 4;
    dhcp_msg->last = (uint8_t*) &(dhcp_msg->op) + (ntohs(udph->len) - 
            sizeof(struct udphdr)) - 1; //Remember, offset
    dhcp_msg->overload = DHCP_OVERLOAD_NONE;
    dhcp_msg->currentblock = DHCP_OVERLOAD_NONE;

    //parse_dhcp_msg(di, &dhcp_msg);

    return 1;
}

int32_t multi_dhcp_create_raw_socket(struct multi_link_info *li, 
        struct multi_dhcp_info *di){
    struct ifreq ifq;
    int32_t sockfd = 0;
    struct sockaddr_ll sll;

    memset(&sll, 0, sizeof(sll));
    memset(&ifq, 0, sizeof(ifq));
    memcpy(&ifq.ifr_name, li->dev_name, strlen((char*) li->dev_name) + 1);
    
    /* Since I am (currently) not interested in the L2-header, SOCK_DGRAM is 
     * used and the L2-header is removed by kernel (man 7 packet). */
    if((sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP))) == -1){
        //perror("Error creating raw socket:");
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Error creating raw socket.\n");
        return -1;
    }

    /* Use this opertunity to get MAC-address of this interface. Stored in the 
     * chaddr-field of every DHCP packet */
    if(ioctl(sockfd, SIOCGIFHWADDR, &ifq) == -1){
        //perror("Could not get info on interface");
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Could not get info on interface\n");
        close(sockfd);
        return -1;
    }

    //Create the filter
    static const struct sock_filter only_dhcp[] = {
        //The best reference to BPF is the original paper, as well as the
        //example I found in LinuxJournal

        //Load the protocol into the accumulator (absolute position 9)
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 9), 
        //Compare accumulator with k,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 3),  
        //MSH is this 4*[k]0xf syntax, a hack for the IP header. Load it into counter
        BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 0), 
        //Load the source and destionation port into accumulator, pos. relative to counter
        BPF_STMT(BPF_LD | BPF_W | BPF_IND, 0), 
        //Compare both ports at once
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, BOOTP_PORT_PAIR, 1, 0), 

        //Return statements
        //Ignore the packet
        BPF_STMT(BPF_RET | BPF_K, 0), 
        //Let the packet through (the value is the number of bytes to let 
        //through, set to high value)
        BPF_STMT(BPF_RET | BPF_K, 0xffffffff), 
    };

    static const struct sock_fprog only_dhcp_prog = {
        .filter = (struct sock_filter *) only_dhcp,
        .len = sizeof(only_dhcp) / sizeof(only_dhcp[0]),
    };

    if(setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &only_dhcp_prog, 
                sizeof(only_dhcp_prog)) == -1){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not attach netlink filter\n");
        perror("Msg: ");
        close(sockfd);
        return -1;
    }

    memcpy(&(di->mac_addr), &(ifq.ifr_hwaddr.sa_data), 
            sizeof(ifq.ifr_hwaddr.sa_data));

    //Will be moved to main, does not belong here
    di->ifidx = li->ifi_idx;

    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_IP);
    sll.sll_ifindex = li->ifi_idx;

    if(bind(sockfd, (struct sockaddr *) &sll, sizeof(sll)) == -1){
        close(sockfd);
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Could not bind socket\n");
        return -1;
    }

    return sockfd;
}

int multi_dhcp_create_udp_socket(struct multi_link_info *li) {
    struct sockaddr_in addr;
    int sock;
    int i = 1;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1){ 
        //perror("Could not establish UDP socket");
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Could not establish UDP socket\n");
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &i, sizeof(i))){
        //perror("Could not set UDP socket to broadcast");
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Could not set UDP socket to broadcast\n");
        return -1;
    }

    if(setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, li->dev_name, 
                strlen((char*) li->dev_name) + 1) < 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Could not bind sock to interface %s "
                "(idx %u)\n", li->dev_name, li->ifi_idx);
        return -1;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = 0;
    addr.sin_port = htons(BOOTP_CLIENT_PORT);

    if (bind(sock, (const struct sockaddr *)&addr, sizeof(addr))){
        close(sock);
        //perror("Could not bind socket to port");
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Could not bind socket to port for interface "
                "%s (idx %u) Error: %s\n", li->dev_name, li->ifi_idx, strerror(errno));
        return -1;
    }

    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) < 0)
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Could not set SO_REUSEADDR on socket %d for "
                "interface %s (idx %u)\n", sock, li->dev_name, li->ifi_idx);

    return sock;
}

