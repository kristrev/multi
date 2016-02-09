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

#include "multi_dhcp_common.h"
#include "multi_dhcp_constants.h"
#include "multi_dhcp_protocol.h"
#include "multi_dhcp_network.h"
#include "multi_link_shared.h"
#include "multi_common.h"

#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <stdio.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <pthread.h>

extern int32_t multi_dhcp_snd_msg_raw(int sock, struct in_addr from_ip, 
        int from_if, struct multi_dhcp_message *msg, uint8_t broadcast);
extern int32_t multi_dhcp_snd_msg_udp(int sock, struct in_addr *to, 
        struct multi_dhcp_message *msg);

/* Functions used to intialize dhcp message, add option, return next option
 * (used for parsing) and writing the last byte of the message. */
//Initializes the message and sets the cookie, cookie defined in RFC
static void multi_dhcp_dm_init(struct multi_dhcp_message *msg) {
  memset(msg, 0, sizeof(*msg));
  msg->pos = msg->options+4;
  memcpy(msg->options, multi_dhcp_vendcookie, 4);
}

/* Helper for adding option */
static void multi_dhcp_dm_add_option(struct multi_dhcp_message *msg, 
        uint8_t option, uint8_t length, void *opt) {
    uint8_t *pos = msg->pos;

    if (&msg->options[MAX_OPT_LEN] - pos < length + 2) 
        abort();

    *pos++ = option;
    *pos++ = length;
    memcpy(pos, opt, length);
    pos += length;

    msg->pos = pos;
}

static uint8_t *multi_dhcp_dm_next_option(struct multi_dhcp_message *msg) {
    uint8_t *pos = msg->pos;
    uint8_t length;

    /* End of packet */
    if (pos >= msg->last)
        return NULL;

    /* skip pad packets */
    while(!*pos) if (++pos >= msg->last) 
        return NULL;

    /* End of option marker */
    while (*pos == 255) {
        /* Overload option handling */
        if (msg->currentblock < msg->overload) { // currentblock: 0,1,3
            msg->currentblock++;
      
            if (msg->overload & DHCP_OVERLOAD_FILE & msg->currentblock) {
	            pos = &msg->file[0];
                msg->last = &msg->file[128];
            } else { // SNAME or BOTH
	            pos = &msg->sname[0];
                msg->last = &msg->sname[64];
                msg->currentblock = DHCP_OVERLOAD_BOTH; // definitely last block
            }

            /* skip pad packets */
            while(!*pos) if (++pos >= msg->last) 
                return NULL;
        } else {
            return NULL;
        }
    }

    /* Actually, this is extra paranoia. Even if pos+1
    * leaves the multi_dhcp_message structure, the next
    * check would catch this as long as we don't
    * try to access an unmapped page ;-)
    */   
    if (pos+1 >= msg->last) 
        return NULL;
  
    length = *(pos+1);
    /* Length overflow */
    if (pos + length + 2 > msg->last) 
        return NULL;

    msg->pos = pos + length+2;
    return pos;
}

//The end option is 255
static void multi_dhcp_dm_finish_options(struct multi_dhcp_message *msg) {
    if (msg->pos == &msg->options[MAX_OPT_LEN]) abort();

    *msg->pos++ = 255;
}

void multi_dhcp_create_dhcp_msg(struct multi_dhcp_info *di){
    struct multi_dhcp_message dhcp_msg;
    uint8_t dhcp_type;
    uint8_t iface_id[7];
    struct in_addr ipaddr;
    uint32_t lease_time = ~0;
    //uint32_t lease_time = htonl(60);
    uint32_t t_now;
    uint8_t ip_addr[INET_ADDRSTRLEN];

    multi_dhcp_dm_init(&dhcp_msg);
    //Unique ID to separate DHCP requests from one another
    dhcp_msg.xid = di->xid; 
    dhcp_msg.op = BOOTP_OPCODE_REQUEST;
    //Found in RFC1700, seems to be a default value for all Ethernet-standards
    dhcp_msg.htype = 1; 
    //Length of MAC-address
    dhcp_msg.hlen = 6; 
    memcpy(dhcp_msg.chaddr, &(di->mac_addr), 6);

    t_now = time(NULL);

    /* Which message to send depends on the client's state. Also, changes state 
     * if needed */
    switch(di->state){
        case INIT:
        case SELECTING:
            /* If I get here, it is either the first packet or a timeout has 
             * occured */
            di->state = SELECTING;
            dhcp_type = DHCP_TYPE_DISCOVER; 
            ipaddr.s_addr = 0;
            multi_dhcp_dm_add_option(&dhcp_msg, DHCP_OPTION_TYPE, 1, 
                    &dhcp_type);
           
            /* According to RFC, it is time of ORIGINAL request */
            if(di->req_sent_time == 0)
                di->req_sent_time = t_now;

            di->req_retrans = t_now + (4 * (di->retrans_count + 1));
            MULTI_DEBUG_PRINT_SYSLOG(stderr,"Sending DHCP DISCOVER (iface idx %u).\n", 
                    di->ifidx);
            di->output_timer = 1;
            break;
        case INIT_REBOOT:
        case REBOOTING:
            di->state = REBOOTING;
            ipaddr.s_addr = 0;
            dhcp_type = DHCP_TYPE_REQUEST;
            multi_dhcp_dm_add_option(&dhcp_msg, DHCP_OPTION_TYPE, 1, 
                    &dhcp_type);
            multi_dhcp_dm_add_option(&dhcp_msg, DHCP_OPTION_REQADDR, 4, 
                    &di->cfg.address.s_addr);

            /* As always, this is a NEW request so time will be set for the 
             * first packet */
            if(di->req_sent_time == 0)
                di->req_sent_time = t_now;

            di->req_retrans = t_now + (4 * (di->retrans_count + 1));

            inet_ntop(AF_INET, &di->cfg.address, (char*) ip_addr, INET_ADDRSTRLEN);
            MULTI_DEBUG_PRINT_SYSLOG(stderr,"REBOOTING and requesting %s, Sending "
                    "DHCP REQUEST (iface idx %u).\n", ip_addr, di->ifidx);
            di->output_timer = 1;
            break;
        case REQUESTING:
            ipaddr.s_addr = 0; 
            dhcp_type = DHCP_TYPE_REQUEST;
            multi_dhcp_dm_add_option(&dhcp_msg, DHCP_OPTION_TYPE, 1, 
                    &dhcp_type);
            multi_dhcp_dm_add_option(&dhcp_msg, DHCP_OPTION_REQADDR, 4, 
                    &di->cfg.address.s_addr);
            multi_dhcp_dm_add_option(&dhcp_msg, DHCP_OPTION_SERVER, 4, 
                    &di->cfg.dhcpd_addr.s_addr);
       
            //Not updating req_sent_time, as this is just a step in a request
            di->req_retrans = t_now + (4 * (di->retrans_count + 1));
            MULTI_DEBUG_PRINT_SYSLOG(stderr,"Sending DHCP REQUEST (iface idx %u).\n", 
                    di->ifidx);
            di->output_timer = 1;
            break;
        case BOUND:
        case RENEWING:
            di->state = RENEWING;
            ipaddr = di->cfg.dhcpd_addr; //Messages for renewing is sent unicast
            dhcp_type = DHCP_TYPE_REQUEST;
            multi_dhcp_dm_add_option(&dhcp_msg, DHCP_OPTION_TYPE, 1, 
                    &dhcp_type);
            dhcp_msg.ciaddr = di->cfg.address.s_addr;

            /* As always, this is a NEW request so time will be set for the 
             * first packet */
            if(di->req_sent_time == 0)
                di->req_sent_time = t_now;

            di->req_retrans = t_now + (4 * (di->retrans_count + 1));
            MULTI_DEBUG_PRINT_SYSLOG(stderr,"RENEWING, sending DHCP REQUEST (iface "
                    "idx %u).\n", di->ifidx);
            di->output_timer = 1;
            break;
        case REBINDING:
            di->state = REBINDING;
            //According to RFC, the old IP must be stored here
            ipaddr = di->cfg.address; 
            dhcp_type = DHCP_TYPE_REQUEST;
            multi_dhcp_dm_add_option(&dhcp_msg, DHCP_OPTION_TYPE, 1, 
                    &dhcp_type);
            dhcp_msg.ciaddr = di->cfg.address.s_addr;

            di->req_retrans = t_now + (4 * (di->retrans_count + 1));
            MULTI_DEBUG_PRINT_SYSLOG(stderr,"REBINDING, sending DHCP REQUEST "
                    "(iface idx %u).\n", di->ifidx);
            di->output_timer = 1;
            break;
        case DECLINE:
            dhcp_type = DHCP_TYPE_DECLINE;
            multi_dhcp_dm_add_option(&dhcp_msg, DHCP_OPTION_TYPE, 1, 
                    &dhcp_type);
            multi_dhcp_dm_add_option(&dhcp_msg, DHCP_OPTION_REQADDR, 4, 
                    &di->cfg.address.s_addr);

            //According to the RFC, move back to init
            //di->state = INIT;
            di->retrans_count = 0;
            di->req_sent_time = 0;
            di->req_retrans = t_now + 10; //Timeout after decline is 10 seconds
            break;
        default:
            break;
    }

    /* Must be done manually due to the pair (see RFC2132) */
    iface_id[0] = 1;
    memcpy(iface_id+1, &(di->mac_addr), 6);
    multi_dhcp_dm_add_option(&dhcp_msg, DHCP_OPTION_CLIENT_IDENTIFIER, 7, 
            iface_id);

    /* The server will only reply when I specify what info I want, naturally. However, RFC states it should return something, check at work tomorrow */
    if(dhcp_type == DHCP_TYPE_DISCOVER || dhcp_type == DHCP_TYPE_REQUEST){
        multi_dhcp_dm_add_option(&dhcp_msg, DHCP_OPTION_OPTIONREQ, 
                sizeof(multi_dhcp_optlist), multi_dhcp_optlist);
        multi_dhcp_dm_add_option(&dhcp_msg, DHCP_OPTION_LEASE, 
                sizeof(lease_time), &lease_time);
    }

    multi_dhcp_dm_finish_options(&dhcp_msg);

    //Send packet. I suspect that the reason I don't receive a unicast reply is
    //because the interface don't have a source IP set
    if(di->state == RENEWING){
        multi_dhcp_snd_msg_udp(di->udp_sock, &ipaddr, &dhcp_msg);
    } else {
        multi_dhcp_snd_msg_raw(di->raw_sock, ipaddr, di->ifidx, &dhcp_msg, 1);
    }
}

/* Copied from dhclient and helper to get values from the option field */
/* Inspired from asm-generic/unaligned.h. gcc3.3.5 and 4.1.2
 * optimize well on i386 */
struct multi_dhcp_u32 { u_int32_t x __attribute__((packed)); };
static inline u_int32_t multi_dhcp_get_unaligned32(const u_int32_t *addr)
{
    const struct multi_dhcp_u32 *ptr = (const struct multi_dhcp_u32 *) addr;
    return ptr->x;
}

static void multi_dhcp_parse_options(struct multi_dhcp_message *msg, 
        struct multi_dhcp_config *cfg) {
    u_int8_t *opt;

    memset(cfg, 0, sizeof(*cfg));

    cfg->address.s_addr = msg->yiaddr;
    cfg->dhcpd_addr.s_addr = msg->siaddr;

    while((opt = multi_dhcp_dm_next_option(msg))) {
        u_int8_t *optdata = opt+2;
        u_int8_t optsize = *(opt+1);
        u_int8_t m;

        switch(*opt) {
            case DHCP_OPTION_TYPE:
                if (optsize == 1)
                    cfg->dhcpmsgtype = *optdata;
                break;
            case DHCP_OPTION_SERVER:
                if (optsize == 4)
                    cfg->dhcpd_addr.s_addr = 
                        multi_dhcp_get_unaligned32((u_int32_t *)optdata);
                break;
            case BOOTP_OPTION_NETMASK:
                if (optsize == 4)
                    cfg->netmask.s_addr = 
                        multi_dhcp_get_unaligned32((u_int32_t *)optdata);
                break;
            case BOOTP_OPTION_GATEWAY:
                if (optsize >= 4)
                    cfg->gateway.s_addr = 
                        multi_dhcp_get_unaligned32((u_int32_t *)optdata);
                break;
            case BOOTP_OPTION_DNS:
                if (!(optsize & 3)) {
                    u_int8_t n;

                    m = optsize / 4;
                    if (m > MAXOPTS) m = MAXOPTS;
                    cfg->dns_num = m;

                    for (n=0; n<m; n++)
                        cfg->dns[n].s_addr = 
                            multi_dhcp_get_unaligned32((u_int32_t *)(optdata+4*n));
                }
                break;
            case BOOTP_OPTION_HOSTNAME:
                if (optsize >= sizeof(cfg->hostname)) 
                    optsize = sizeof(cfg->hostname)-1;
                memcpy(cfg->hostname, optdata, optsize);
                cfg->hostname[optsize] = 0;
                break;
            case BOOTP_OPTION_DOMAIN:
                if (optsize >= sizeof(cfg->domainname)) 
                    optsize = sizeof(cfg->domainname)-1;
                memcpy(cfg->domainname, optdata, optsize);
                cfg->domainname[optsize] = 0;
                break;
            case BOOTP_OPTION_BROADCAST:
                if (optsize == 4)
                    cfg->broadcast.s_addr = 
                        multi_dhcp_get_unaligned32((u_int32_t *)optdata);
                break;
            case DHCP_OPTION_LEASE:
                if (optsize == 4)
                    cfg->lease = 
                        ntohl(multi_dhcp_get_unaligned32((u_int32_t *)optdata));
                break;
            case DHCP_OPTION_OVERLOAD:
                if (optsize == 1 && *optdata <= DHCP_OVERLOAD_BOTH)
                    msg->overload = *optdata;
                break;
            case DHCP_OPTION_T1:
                if (optsize == 4)
                    cfg->t1 = 
                        ntohl(multi_dhcp_get_unaligned32((u_int32_t *)optdata));
                break;
            case DHCP_OPTION_T2:
                if (optsize == 4)
                    cfg->t2 = 
                        ntohl(multi_dhcp_get_unaligned32((u_int32_t *)optdata));
                break;
        }
    }
}

void multi_dhcp_parse_dhcp_msg(struct multi_dhcp_info *di, 
        struct multi_dhcp_message *dm, struct multi_link_info *li){
    struct multi_dhcp_config cfg;
    uint32_t t_now, t_diff;
    uint8_t ipaddr[INET_ADDRSTRLEN];
    uint8_t baddr[INET_ADDRSTRLEN];
    uint8_t gwaddr[INET_ADDRSTRLEN];
    uint8_t netmask[INET_ADDRSTRLEN];

    multi_dhcp_parse_options(dm, &cfg);

    if (dm->xid != di->xid || dm->hlen != 6 || 
            memcmp(dm->chaddr, &(di->mac_addr),6)){ 
        //fprintf(stderr, "Message intended for someone else!\n");
        return;
    }

    switch(di->state){
        case SELECTING:
            //One typical scenario here is if the lease expires before the 
            //DHCP ACK for final REBIND is received
            if(cfg.dhcpmsgtype != DHCP_TYPE_OFFER){ 
                MULTI_DEBUG_PRINT_SYSLOG(stderr,"Mismatch state. In INIT but did not "
                        "get OFFER. Got %u\n", cfg.dhcpmsgtype);
                return;
            }

            /* Move on to the next state, retrans count must be reset */
            di->retrans_count = 0;

            MULTI_DEBUG_PRINT_SYSLOG(stderr,"Received DHCP OFFER on interface %s "
                    "(iface idx %u), will send DHCP REQUEST\n", li->dev_name, 
                    li->ifi_idx);

            di->cfg = cfg;
            di->state = REQUESTING; 
            multi_dhcp_create_dhcp_msg(di);
            break;
        case RENEWING:
        case REBINDING:
        case REQUESTING:
        case REBOOTING:
            /* All these states  */
            if(cfg.dhcpmsgtype == DHCP_TYPE_NAK){
                /* According to the RFC, a NAK involves moving straight back to
                 * INIT and resending request. Moving to INIT implies resetting
                 * variables and state, just in case */
                MULTI_DEBUG_PRINT_SYSLOG(stderr,"Got NAK in state %u. Resetting and "
                        "retrying DISCOVER! (iface idx %u)\n", di->state, 
                        di->ifidx);
                di->state = INIT;
                di->req_sent_time = 0;
                //Since next packet is sent immideatly, this can 0 (as opposed 
                //to -1 for ACK)
                di->retrans_count = 0; 

                /* Set state as waiting. I can here if a) rebooting fails b)
                 * requesting fails c) renewing fails d) rebinding fails. In the
                 * last two, the link can be in UP state */
                pthread_mutex_lock(&(li->state_lock));
                li->state = WAITING_FOR_DHCP;
                pthread_mutex_unlock(&(li->state_lock));

                multi_dhcp_create_dhcp_msg(di);
            } else if(cfg.dhcpmsgtype == DHCP_TYPE_ACK){
                //Always decline DHCP address
                di->cfg = cfg; //Just in case, I know these are the good values
                
                di->state = BOUND;
                
                inet_ntop(AF_INET, &(cfg.address), (char*) ipaddr, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(cfg.broadcast), (char*) baddr, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(cfg.gateway), (char*) gwaddr, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(cfg.netmask), (char*) netmask, INET_ADDRSTRLEN);
                
                //Do the timeout calculation. Be warned that inet_ntoa is NOT
                    //reentrant. In other words, the IP adresses are wrong!
                MULTI_DEBUG_PRINT_SYSLOG(stderr,"Got DHCP ACK on interface %s "
                        "(iface idx %u). %s will be bound to IP: %s Broadcast: "
                        "%s Gateway: %s Netmask %s (%u) Lease: %u T1: %u T2: "
                        "%u\n", li->dev_name, li->ifi_idx, li->dev_name, 
                        ipaddr, baddr, gwaddr, netmask, 
                        32 - (ffs(ntohl(cfg.netmask.s_addr)) - 1), 
                        cfg.lease, cfg.t1, cfg.t2);


                //TODO: I need some variable or check to prevent adding the same IP twice. Compare cfg is maybe sufficient? Or at least address?
                pthread_mutex_lock(&(li->state_lock));

                /* This is needed if one interface switches network. Otherwise,
                 * the main thread will not know that it has to clean up (it
                 * will just see a new set of addresses)! */
                /* Need to wireless access points in order to test this, with
                 * different subnets */
                if(li->cfg.address.s_addr != 0 && 
                    (li->cfg.address.s_addr != cfg.address.s_addr || 
                     li->cfg.broadcast.s_addr != cfg.broadcast.s_addr || 
                     li->cfg.gateway.s_addr != cfg.gateway.s_addr || 
                     li->cfg.netmask.s_addr != cfg.netmask.s_addr)){

                    li->state = DHCP_IP_CHANGED;
                    li->new_cfg = cfg;
                    multi_dhcp_notify_link_module(li->write_pipe);
                } else{ 
                    li->cfg = cfg;

                    /* This is correct becuase if the information has not
                     * changed, then there is no need to update the state. The
                     * cfg must be updated due to leases and so on */
                    if(li->state != LINK_UP){
                        li->state = GOT_IP_DHCP;
                        multi_dhcp_notify_link_module(li->write_pipe);
                    }
                }

                pthread_mutex_unlock(&(li->state_lock));

                t_now = time(NULL);
                t_diff = t_now - di->req_sent_time;

                di->lease = cfg.lease;
                di->t1 = cfg.t1 ? cfg.t1 : cfg.lease / 2;
                di->t2 = cfg.t2 ? cfg.t2 : cfg.lease * 0.875;

                /* Not exactly sure what to do in this case */                
                assert(t_diff < di->t1 || t_diff < di->t2);
                assert(di->t1 < di->t2);

                /* Lease is from WHEN the request was sent */
                di->lease -= t_diff;
                di->t1 -= t_diff;
                di->t2 -= t_diff;

                /* Convert values to be absolute */
                di->lease += t_now;
                di->t1 += t_now;
                di->t2 += t_now;
 
                /* Every packet has been accounted for, so timers and everything can be reset */
                di->req_sent_time = 0;
                //This will overflow, but it is ok. When the next timeout (T1) 
                //is triggered, retrans_count will be increased by 1 and, thus,
                //be 0 again (but a little hackish)

                di->retrans_count = -1; 
                /* New timeout event started */
                di->output_timer = 1;
           }
        default:
            break;
    }
}

