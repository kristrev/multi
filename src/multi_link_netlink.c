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

#include <stdio.h>
#include <sys/types.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <string.h>
#include <linux/fib_rules.h> //The rules-thing
#include <stdlib.h>
#include <libmnl/libmnl.h>

#include "multi_link_core.h"
#include "multi_link_netlink.h"
#include "multi_link_shared.h"
#include "multi_link_filter.h"

extern struct rtnl_handle multi_link_rth;
//multi_link_filter
extern int32_t multi_link_filter_ppp(const struct nlmsghdr *nlh, void *data); 
extern int32_t multi_link_filter_ap(const struct nlmsghdr *nlh, void *data);
//multi_link_core
extern int32_t multi_link_filter(uint32_t seq, mnl_cb_t cb, void *arg); 

/* Add/delete ip rule */
static int32_t multi_link_modify_rule(uint32_t msg_type, uint32_t flags, 
        uint32_t table_id, struct multi_link_info *li, uint8_t addr_len,
        uint8_t dir, uint32_t prio, const char *ifname){
    uint8_t buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct rtmsg *rt;

    memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = msg_type;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    nlh->nlmsg_seq = 0;

    rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rt->rtm_family = AF_INET;
    rt->rtm_dst_len = 0;
    rt->rtm_table = table_id; //The table to perform the lookup in
    rt->rtm_protocol = RTPROT_BOOT;
    rt->rtm_scope = RT_SCOPE_UNIVERSE;
    rt->rtm_type = RTN_UNICAST;
    
    mnl_attr_put_u32(nlh, FRA_PRIORITY, prio);

    if (dir == FRA_SRC)
        rt->rtm_src_len = addr_len;
    else if (dir == FRA_DST)
        rt->rtm_dst_len = addr_len;

    if (rt->rtm_src_len || rt->rtm_dst_len)
        mnl_attr_put_u32(nlh, dir, li->cfg.address.s_addr);

    if (ifname)
        mnl_attr_put_strz(nlh, FRA_IFNAME, ifname);

    if(mnl_socket_sendto(multi_link_nl_set, nlh, nlh->nlmsg_len) < 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Could not send rule to kernel "
                "(can be ignored if caused by an interface that went down, "
                "iface idx %u)\n", li->ifi_idx);
        return -1;
    }

    return 0;

}

/* Add/delete gateway */
static int32_t multi_link_modify_gateway(uint32_t msg_type, uint32_t flags, 
        uint32_t table_id, struct multi_link_info *li, uint32_t metric){
    uint8_t buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct rtmsg *rt;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = msg_type;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    nlh->nlmsg_seq = 0;

    rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
    rt->rtm_family = AF_INET;
    //There is no destination (the destination is global, i.e. netmask 0)
    rt->rtm_dst_len = 0; 
    rt->rtm_table = table_id;
    rt->rtm_protocol = RTPROT_UNSPEC;

    /* This is all copied from iproute  */
    if(msg_type != RTM_DELROUTE){
        rt->rtm_scope = RT_SCOPE_UNIVERSE; 
        rt->rtm_type = RTN_UNICAST;
        rt->rtm_protocol = RTPROT_BOOT;
    } else 
        rt->rtm_scope = RT_SCOPE_NOWHERE;

    if(li->cfg.gateway.s_addr > 0)
        mnl_attr_put_u32(nlh, RTA_GATEWAY, li->cfg.gateway.s_addr);

    mnl_attr_put_u32(nlh, RTA_PREFSRC, li->cfg.address.s_addr);
    mnl_attr_put_u32(nlh, RTA_OIF, li->ifi_idx);

	if(metric)
        mnl_attr_put_u32(nlh, RTA_PRIORITY, metric);

    if(mnl_socket_sendto(multi_link_nl_set, nlh, nlh->nlmsg_len) < 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Could not send gateway to kernel "
                "(can be ignored if caused by an interface that went down, "
                "iface idx %u)\n", li->ifi_idx);
        return -1;
    }

    return 0;
}

/* Adds/deletes route. The reason for having metric as a seperate parameter is
 * that the value depends on wether this is the private table (0) or not. If the
 * route is intended for the private table, then ignore metric */
static int32_t multi_link_modify_route(uint32_t msg_type, uint32_t flags, 
        uint32_t table_id, struct multi_link_info *li, uint32_t metric){
    uint8_t buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct rtmsg *rt;
    uint32_t nw_ip = 0;

    //The desired destination IP is store in different places for PPP and
    //"normal" interfaces. This is the network route!
    if(li->state == GOT_IP_PPP || li->state == LINK_UP_PPP)
        nw_ip = li->cfg.broadcast.s_addr;
    else
        nw_ip = li->cfg.address.s_addr & li->cfg.netmask.s_addr;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = msg_type;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    nlh->nlmsg_seq = 0;

    rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtmsg));
 
    rt->rtm_scope = RT_SCOPE_NOWHERE;
    rt->rtm_type = RTN_UNICAST;
    rt->rtm_family = AF_INET;
    rt->rtm_dst_len = 32 - (ffs(ntohl(li->cfg.netmask.s_addr)) - 1);
    rt->rtm_table = table_id;

    if(msg_type != RTM_DELROUTE){
        rt->rtm_protocol = RTPROT_BOOT;
        rt->rtm_scope = RT_SCOPE_LINK;
    }

    mnl_attr_put_u32(nlh, RTA_DST, nw_ip);
    mnl_attr_put_u32(nlh, RTA_PREFSRC, li->cfg.address.s_addr);
    mnl_attr_put_u32(nlh, RTA_OIF, li->ifi_idx);

    if(metric)
        mnl_attr_put_u32(nlh, RTA_PRIORITY, metric);

    if(mnl_socket_sendto(multi_link_nl_set, nlh, nlh->nlmsg_len) < 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Could not send private route to kernel "
                "(can be ignored if caused by an interface that went down, "
                "iface idx %u)\n", li->ifi_idx);
        return -1;
    }

    return 0;
}

/* Adds or deletes the IP of an interface. This function is never called for PPP
 * interfaces, thus, there are no special cases. */
static int32_t multi_link_modify_ip(uint32_t msg_type, uint32_t flags, 
        struct multi_link_info *li){
    uint8_t buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct ifaddrmsg *ifa;

    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = msg_type;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    nlh->nlmsg_seq = 0;

    ifa = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifaddrmsg));
    
    /* Fill in info related to address */
    ifa->ifa_family = AF_INET; //Currently only IPv4

    //To avoid this rule that is generated automatically, set bitlen to 32
    ifa->ifa_prefixlen = 32 - (ffs(ntohl(li->cfg.netmask.s_addr)) - 1); 
    //Only reason for changing this is if loopback
    ifa->ifa_scope = RT_SCOPE_UNIVERSE; 
    ifa->ifa_index = li->ifi_idx;

    mnl_attr_put_u32(nlh, IFA_LOCAL, li->cfg.address.s_addr);
    mnl_attr_put_u32(nlh, IFA_ADDRESS, li->cfg.address.s_addr);

    if(li->cfg.broadcast.s_addr)
        mnl_attr_put_u32(nlh, IFA_BROADCAST, li->cfg.broadcast.s_addr);

    if(mnl_socket_sendto(multi_link_nl_set, nlh, nlh->nlmsg_len) < 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Could not send IP to kernel (can be ignored "
                "if caused by an interface that went down, iface idx %u)\n", 
                li->ifi_idx);
        return -1;
    }

    return 0;
}

void multi_link_get_iface_info(struct multi_link_info *li){
    //MNL_SOCKET_BUFFER_SIZE is 8k, which is the max nlmsg size (see
    //linux/netlink.h)
    uint8_t buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct rtgenmsg *rt;
    uint32_t seq;

    //It seems like I cant request one interface, has to dump!
    ////Play with this later and see what is up
    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETADDR;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = time(NULL); //How will this work with event? Send 0?
    rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
    //I need all interfaces, also those without IP (check)
    rt->rtgen_family = AF_UNSPEC; 

    if(mnl_socket_sendto(multi_link_nl_request, nlh, nlh->nlmsg_len) < 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Cannot request info dump\n");
        return;
    }

    if(li->state == LINK_DOWN_PPP)
        multi_link_filter(seq, multi_link_filter_ppp, (void*) li);
    else if(li->state == LINK_DOWN_AP)
        multi_link_filter(seq, multi_link_filter_ap, (void*) li);
}

/* Function used to remove the information added automatically by pppd  */
/* TODO: Add error codes! */
void multi_link_remove_ppp(struct multi_link_info *li){
    if(!multi_link_modify_route(RTM_DELROUTE, 0, RT_TABLE_MAIN, li, 0)){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Removed automatic PPP route!\n");
    } else{
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Failed to remove automatic PPP route!\n");
        return;
    }
}

void multi_link_remove_ap(struct multi_link_info *li){
    if(!multi_link_modify_route(RTM_DELROUTE, 0, RT_TABLE_MAIN, li, 0)){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Removed automatic AP route!\n");
    } else{
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Failed to remove automatic AP route!\n");
        return;
    }
}

void multi_link_configure_link(struct multi_link_info *li){
    /* Add IP address. PPP/AP has already set the IP of the interface*/
    //It is safe to do this twice in case of GOT_IP_STATIC_UP/GOT_IP_STATIC. An
    //interface can only be assigned the same IP address one time. Error will be
    //returned the following times.
    if(li->state != GOT_IP_PPP && li->state != GOT_IP_AP)
        multi_link_modify_ip(RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE, li);

    //Only set IP when link is only up (not running) */
    if(li->state == GOT_IP_STATIC_UP)
        return;

    /* Use metric as table ID for now */
    multi_link_modify_route(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_APPEND, 
            li->metric, li, 0);

        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Done setting direct routes (iface %s idx %u)\n", 
            li->dev_name, li->ifi_idx); 

    if(li->state == GOT_IP_AP || (li->state == GOT_IP_STATIC && 
                !li->cfg.gateway.s_addr)){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Not setting gateway for %s (idx %u)\n", 
                li->dev_name, li->ifi_idx); 
    } else {
        multi_link_modify_gateway(RTM_NEWROUTE, NLM_F_CREATE | NLM_F_APPEND, 
            li->metric, li, 0);
        //Delete the route that is automatically added by kernel when we add an
        //address with mask < 32
        multi_link_modify_route(RTM_DELROUTE, NLM_F_CREATE | NLM_F_APPEND, 
            RT_TABLE_MAIN, li, 0);
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Done setting routes in main table "
                "(iface %s idx %u)\n", li->dev_name, li->ifi_idx);
    }

    multi_link_modify_rule(RTM_NEWRULE, NLM_F_CREATE | NLM_F_EXCL, li->metric, 
            li, 32, FRA_SRC, ADDR_RULE_PRIO, NULL);
    multi_link_modify_rule(RTM_NEWRULE, NLM_F_CREATE | NLM_F_EXCL, li->metric, 
            li, 32 - (ffs(ntohl(li->cfg.netmask.s_addr)) - 1), FRA_DST,
            NW_RULE_PRIO, NULL);
    multi_link_modify_rule(RTM_NEWRULE, NLM_F_CREATE | NLM_F_EXCL, li->metric, 
            li, 0, 0, DEF_RULE_PRIO + li->metric, "lo");

    MULTI_DEBUG_PRINT_SYSLOG(stderr, "Done adding rule (iface %s idx %u)\n", 
            li->dev_name, li->ifi_idx);
}

/* Maybe replace this with a command for flushing */
void multi_link_remove_link(struct multi_link_info *li){
    multi_link_modify_rule(RTM_DELRULE, 0, li->metric, li, 32, FRA_SRC,
            ADDR_RULE_PRIO, NULL);
    multi_link_modify_rule(RTM_DELRULE, 0, li->metric, 
            li, 32 - (ffs(ntohl(li->cfg.netmask.s_addr)) - 1), FRA_DST,
            NW_RULE_PRIO, NULL);
    multi_link_modify_rule(RTM_DELRULE, NLM_F_CREATE | NLM_F_EXCL, li->metric, 
            li, 0, 0, DEF_RULE_PRIO + li->metric, "lo");

    /* This seems to be done by the kernel, but does it depend on something or not? Maybe have a check here */
    if(li->state != GOT_IP_AP)
        multi_link_modify_gateway(RTM_DELROUTE, 0, li->metric, li, 0);
    
    multi_link_modify_route(RTM_DELROUTE, 0, li->metric, li, 0);

    /* Delete IP address */
    if(li->state != GOT_IP_PPP && li->state != LINK_UP_PPP && 
            li->state != GOT_IP_AP && li->state != LINK_UP_AP && 
            li->state != LINK_UP_STATIC)
        multi_link_modify_ip(RTM_DELADDR, 0, li);

    MULTI_DEBUG_PRINT_SYSLOG(stderr, "Cleaned up after %s (iface idx %u)\n", 
            li->dev_name, li->ifi_idx);
}
