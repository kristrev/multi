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

#include <stdint.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/fib_rules.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <string.h>
#include <iwlib.h>
#include <libmnl/libmnl.h>
#include <arpa/inet.h>

#include "multi_shared.h"
#include "multi_link_core.h"
#include "multi_link_filter.h"
#include "multi_link_shared.h"
#include "multi_link_netlink.h"

#include "multi_macros.h"
#include "multi_cmp.h"

extern struct multi_link_links_head multi_link_links_2;
extern uint32_t multi_link_num_links; 
extern struct multi_link_info *multi_link_create_new_link(uint8_t* dev_name, 
        uint32_t metric);

//Read the documentation, this basically does what the old parse does (put in
//tb), but is is much more flexible
int32_t multi_link_fill_rtattr(const struct nlattr *attr, void *data){
    //TB is an array, remember that
    const struct nlattr **tb = data;
    int32_t type = mnl_attr_get_type(attr);

    //Could do some validation here, for example
    //Any attribute that is after IFLA_MAX is not valid in userspace, ignore
    if(mnl_attr_type_valid(attr, IFLA_MAX) <0)
        return MNL_CB_OK;

    tb[type] = attr;
    return MNL_CB_OK;

}

/* Check if a link is WLAN, and if so, if it is master/monitor (ignore if that
 * is the case). Returns the mode.  */
uint8_t multi_link_check_wlan_mode(uint8_t *dev_name){
    int32_t wlan_sock = 0; //Socket for communicating with iwlib
    struct wireless_config wcfg; //Malloc this one?
    int32_t retval = 0;

    if((wlan_sock = iw_sockets_open()) > 0)
        //This can be optimised, MODE is just a normal ioctl
        if(!iw_get_basic_config(wlan_sock, (char*) dev_name, &wcfg)){
            if(wcfg.mode == 3 || wcfg.mode == 6)
                return wcfg.mode;
        } else
            close(wlan_sock);

    return 0;
}

int32_t multi_link_filter_links(const struct nlmsghdr *nlh, void *data){
    //nlattr is the generic form of rtattr
    struct nlattr *tb[IFLA_MAX + 1] = {};
    struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);
    uint8_t *devname;
    struct multi_link_info *li;
	struct multi_link_info_static *li_static = NULL;
    uint8_t wireless_mode = 0;

    mnl_attr_parse(nlh, sizeof(*ifi), multi_link_fill_rtattr, tb);

    if (!tb[IFLA_IFNAME]) {
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Missing interface name\n");
        return MNL_CB_OK;
    }

    devname = (uint8_t*) mnl_attr_get_str(tb[IFLA_IFNAME]);

    if (!strncmp(devname, "veth", 4) ||
        !strncmp(devname, "ifb", 3) ||
        ifi->ifi_type == ARPHRD_VOID ||
        (ifi->ifi_type == ARPHRD_NONE && strncmp(devname, "wwan", 4) && strncmp(devname, "nlw_1", 4)) ||
        ifi->ifi_type == ARPHRD_TUNNEL ||
        ifi->ifi_flags & IFF_LOOPBACK)
        return MNL_CB_OK;

    if((wireless_mode = multi_link_check_wlan_mode(devname))) {
        if (wireless_mode == 6) {
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "Interface %s is wireless monitor, "
                    "ignoring\n", devname);
            return MNL_CB_OK;
        }
    }

    if (!tb[IFLA_OPERSTATE])
        return MNL_CB_OK;

    //Interface is up, do normal operation
    //Last one is for interfaces that are UP, but not running (for example
    //no LAN cable)
    TAILQ_FIND_CUSTOM(li_static, &multi_shared_static_links,
        list_ptr, devname, multi_cmp_devname);

    if(ifi->ifi_flags & IFF_RUNNING || ((ifi->ifi_flags & IFF_UP) && 
                li_static)){
        //TODO: Assumes that there is initially always room for every link
        if (li_static != NULL) {
            if(li_static->proto == PROTO_IGNORE){
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Ignoring %s (idx %d) \n", 
                        devname, ifi->ifi_index);
                return MNL_CB_OK;
            } else {
                li = multi_link_create_new_link(devname, li_static->metric);
            }
        } else { 
            /* Allocate a new link, add to list and start DHCP */
            li = multi_link_create_new_link(devname, 0);
        }

        if (!li) {
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not create link object\n");
            return MNL_CB_OK;
        }

        /* If link exists in static link list, set link to GOT_STATIC */
        if (li_static != NULL && li_static->proto == PROTO_STATIC) {
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "Link %s assigned static IP\n", devname);

            //I will only set IP, when interface is only up.
            if (ifi->ifi_flags & IFF_RUNNING) {
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Link %s is RUNNING\n", devname);
                li->state = GOT_IP_STATIC;
            } else if (ifi->ifi_flags & IFF_UP) {
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Link %s is UP\n", devname);
                                li->state = GOT_IP_STATIC_UP;
            }

            li->cfg = li_static->cfg_static;
        } else if (ifi->ifi_type == ARPHRD_PPP) {
            /* PPP will be dealt with separatley, since they get the IP
             * remotely by themself */
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "Link %s is PPP!\n", devname);
            li->state = LINK_DOWN_PPP;
        } else if (wireless_mode == 3) {
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "Link %s is wireless access point\n", 
                    devname);
            li->state = LINK_DOWN_AP;                
        } else {
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "Found link %s\n", devname);
        }

        //The order in which links are stored in this list is not important
        LIST_INSERT_HEAD(&multi_link_links_2, li, next);
        ++multi_link_num_links;
    }

    return MNL_CB_OK;
}

int32_t multi_link_filter_ipaddr(const struct nlmsghdr *nlh, void *data){
    struct ip_info *ip_info = (struct ip_info *) data;
    struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);
    struct nlattr *tb[IFLA_MAX + 1] = {};
    struct filter_msg *msg;
    struct multi_link_info *li = NULL;
    struct multi_link_info_static *li_static = NULL;
    char devname[IF_NAMESIZE+1] = {0};

    if (if_indextoname(ifa->ifa_index, devname))
        TAILQ_FIND_CUSTOM(li_static, &multi_shared_static_links, list_ptr,
                devname, multi_cmp_devname);

    if (li_static && li_static->proto == PROTO_IGNORE)
        return MNL_CB_OK;

    //The reason I need to check in multi_link_links is interfaces that are
    //ignored, or that have come up after I dumped the interface info. The first
    //case interfaces should be ignored, while the second case interfaces will
    //be seen later
    LIST_FIND_CUSTOM(li, &multi_link_links_2, next, ifa, multi_cmp_ifidx_flush);

    if(li){
        //Copy the nlmsg, as I will recycle it later when I delete everything!
        msg = (struct filter_msg*) malloc(nlh->nlmsg_len + 
                sizeof(TAILQ_ENTRY(filter_msg)));
        memcpy(&(msg->nlh), nlh, nlh->nlmsg_len);
        TAILQ_INSERT_TAIL(&(ip_info->ip_addr_n), msg, list_ptr);

        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Deleting address for interface %u\n",
                ifa->ifa_index);
    }

    return MNL_CB_OK;
}

/* Update the provide PPP link with information about the interface  */
int32_t multi_link_filter_ppp(const struct nlmsghdr *nlh, void *data){
    struct multi_link_info *li = (struct multi_link_info *) data;
    struct nlattr *tb[IFLA_MAX + 1] = {};
    struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);
    struct sockaddr_in sa;
    uint8_t addr_buf[INET_ADDRSTRLEN];

    if(ifa->ifa_index != li->ifi_idx)
        return MNL_CB_OK;

    mnl_attr_parse(nlh, sizeof(*ifa), multi_link_fill_rtattr, tb);

     if(tb[IFA_LOCAL] && tb[IFA_ADDRESS]){
        li->cfg.address.s_addr = mnl_attr_get_u32(tb[IFA_LOCAL]);
        li->cfg.broadcast.s_addr = mnl_attr_get_u32(tb[IFA_ADDRESS]);
        li->cfg.gateway.s_addr = 0;
        inet_pton(AF_INET, "255.255.255.255", &(li->cfg.netmask));
        li->state = GOT_IP_PPP;
        
        sa.sin_family = AF_INET;
        sa.sin_addr = li->cfg.address;
        inet_ntop(AF_INET, &(sa.sin_addr), (char*) addr_buf, INET_ADDRSTRLEN);
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Local address: %s \n", addr_buf);

        sa.sin_family = AF_INET;
        sa.sin_addr = li->cfg.broadcast;
        inet_ntop(AF_INET, &(sa.sin_addr), (char*) addr_buf, INET_ADDRSTRLEN);
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Remote address: %s\n", addr_buf);
    }

    return MNL_CB_OK;
}

/* Update the provide PPP link with information about the interface  */
int32_t multi_link_filter_ap(const struct nlmsghdr *nlh, void *data){
    struct multi_link_info *li = (struct multi_link_info *) data;
    struct nlattr *tb[IFLA_MAX + 1] = {};
    struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);
    struct sockaddr_in sa;
    uint8_t addr_buf[INET_ADDRSTRLEN];
    uint32_t mask = 0;

    //This ifa_scope is just a hack, check in more detail what happens when I
    //create an AP
    if(ifa->ifa_index != li->ifi_idx)
        return MNL_CB_OK;

    //Access point is also configured with an IPv6 route, not interested in that
    //now
    if(ifa->ifa_family == AF_INET6)
        return MNL_CB_OK; 

    mnl_attr_parse(nlh, sizeof(*ifa), multi_link_fill_rtattr, tb);

     if(tb[IFA_ADDRESS]){
        li->cfg.address.s_addr = mnl_attr_get_u32(tb[IFA_ADDRESS]);        

        //Logic is simple. Set the first bit, movie it the number of 0's to the
        //left, subtract 1 (so that all lesser bits are 1) and flip
        mask = htonl(~((1 << (32 - ifa->ifa_prefixlen)) - 1));
        li->cfg.netmask.s_addr = mask;

        li->state = GOT_IP_AP;

        sa.sin_family = AF_INET;
        sa.sin_addr = li->cfg.address;
        inet_ntop(AF_INET, &(sa.sin_addr), (char*) addr_buf, INET_ADDRSTRLEN);
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Local address: %s \n", addr_buf);

        sa.sin_family = AF_INET;
        sa.sin_addr = li->cfg.netmask;
        inet_ntop(AF_INET, &(sa.sin_addr), (char*) addr_buf, INET_ADDRSTRLEN);
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Netmask: %s\n", addr_buf);
    }

    return MNL_CB_OK;
}

/* Get the ip rules that belong to the current interfaces */
int32_t multi_link_filter_iprules(const struct nlmsghdr *nlh, void *data){
    struct ip_info *ip_info = (struct ip_info *) data;
    struct rtmsg *rt = mnl_nlmsg_get_payload(nlh);
    struct nlattr *tb[FRA_MAX + 1] = {};
    char *iface_name = NULL;
    struct filter_msg *msg;
    uint32_t fra_priority = 0;

    mnl_attr_parse(nlh, sizeof(*rt), multi_link_fill_rtattr, tb);

    if(!tb[FRA_PRIORITY])
        return MNL_CB_OK;

    fra_priority = mnl_attr_get_u32(tb[FRA_PRIORITY]);

    if (fra_priority != ADDR_RULE_PRIO &&
        fra_priority != NW_RULE_PRIO &&
        (fra_priority < (DEF_RULE_PRIO + 1) || fra_priority > DEF_RULE_MAX))
        return MNL_CB_OK;

    //The last part of this check is not perfect, but it works for now. Will
    //break when someone adds a rule with a larger priority
    if (fra_priority != ADDR_RULE_PRIO && fra_priority != NW_RULE_PRIO &&
        fra_priority <= DEF_RULE_PRIO)
        return MNL_CB_OK;

    //TODO: Add a check for interface here as well, do our best not to do
    //anything with interfaces that should be ignored?
    MULTI_DEBUG_PRINT_SYSLOG(stderr,  "Added rule with id %u to flush list\n", 
            fra_priority);

    /* Add the rule nlmsg to list */
    msg = (struct filter_msg*) malloc(nlh->nlmsg_len + 
            sizeof(TAILQ_ENTRY(filter_msg)));
    memcpy(&(msg->nlh), nlh, nlh->nlmsg_len);
    TAILQ_INSERT_TAIL(&(ip_info->ip_rules_n), msg, list_ptr);

    return MNL_CB_OK;
}

static uint8_t multi_link_filter_cmp_def_rule(
        struct multi_link_filter_iprule *filter_iprule,
        uint32_t prio)
{
    struct multi_link_info *li_itr = multi_link_links_2.lh_first;

    //Rules are returned in order, so this will take care of any duplicate
    //rules. We should never have any 91000 + X rules
    //pointing to the same table
    if (prio  == filter_iprule->last_prio)
        return 1;

    filter_iprule->last_prio = prio;

    //In case we have missed a dellink, check if there is a network with
    //matching metric. We don't need to check for multiple entries with same
    //metric, that is taken care of by the previous check
    while (li_itr != NULL) {
        if (li_itr->metric == prio)
            break;

        li_itr = li_itr->next.le_next;
    }

    return li_itr == NULL;
}

static uint8_t multi_link_filter_cmp_nw_addr_rule(struct nlattr *tb[],
        struct multi_link_info *li)
{
    uint32_t rule_addr, target_table;
    struct multi_link_info *li_itr = multi_link_links_2.lh_first;
    
    if ((!tb[FRA_SRC] && !tb[FRA_DST]) || (tb[FRA_SRC] && tb[FRA_DST]))
        return 0;

    if (tb[FRA_SRC])
        rule_addr = mnl_attr_get_u32(tb[FRA_SRC]);
    else if(tb[FRA_DST])
        rule_addr = mnl_attr_get_u32(tb[FRA_DST]);

    if (rule_addr != li->cfg.address.s_addr)
        return 0;

    target_table = mnl_attr_get_u32(tb[FRA_TABLE]);

    //Need to check if there exists an interface with this IP using this table
    while (li_itr != NULL) {
        if (li != li_itr &&
            li_itr->cfg.address.s_addr == rule_addr &&
            li_itr->metric == target_table)
            break;

        li_itr = li_itr->next.le_next;
    }

    if (li_itr != NULL)
        return 0;
    else
        return 1;
}

//Create a list of rules matching the given source address
int32_t multi_link_filter_iprules_addr(const struct nlmsghdr *nlh, void *data)
{
    struct ip_info *ip_info = (struct ip_info *) data;
    struct rtmsg *rt = mnl_nlmsg_get_payload(nlh);
    struct nlattr *tb[FRA_MAX + 1] = {};
    char *iface_name = NULL;
    struct filter_msg *msg;
    uint32_t target_table, prio;
    struct multi_link_filter_iprule *filter_iprule = ip_info->data;
    struct multi_link_info *li = filter_iprule->li, *li_itr;
    uint8_t should_delete = 0;

    mnl_attr_parse(nlh, sizeof(*rt), multi_link_fill_rtattr, tb);

    if (!tb[FRA_PRIORITY] || !tb[FRA_TABLE])
        return MNL_CB_OK;

    prio = mnl_attr_get_u32(tb[FRA_PRIORITY]);

    if (prio != ADDR_RULE_PRIO && prio != NW_RULE_PRIO &&
        (prio < (DEF_RULE_PRIO + 1) || prio > DEF_RULE_MAX))
        return MNL_CB_OK;

    if (prio > (DEF_RULE_PRIO + 1) && prio <= DEF_RULE_MAX)
        should_delete = multi_link_filter_cmp_def_rule(filter_iprule, prio);
    else
        should_delete = multi_link_filter_cmp_nw_addr_rule(tb, li);

    if (!should_delete) {
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Ignore (sanity) rule pref %u table %u\n",
                mnl_attr_get_u32(tb[FRA_PRIORITY]), target_table);
        return MNL_CB_OK;
    }

    //Add check for other IPs
    msg = (struct filter_msg*) malloc(nlh->nlmsg_len +
            sizeof(TAILQ_ENTRY(filter_msg)));

    if (msg == NULL) {
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Can't allocate memory for rule message\n");
        return MNL_CB_ERROR;
    }

    MULTI_DEBUG_PRINT_SYSLOG(stderr,  "Delete (sanity) rule pref %u\n", 
            prio);

    memcpy(&(msg->nlh), nlh, nlh->nlmsg_len);
    TAILQ_INSERT_TAIL(&(ip_info->ip_rules_n), msg, list_ptr);
    return MNL_CB_OK;
}

int32_t multi_link_filter_iproutes(const struct nlmsghdr *nlh, void *data){
    struct ip_info *ip_info = (struct ip_info *) data;
    struct rtmsg *table_i = mnl_nlmsg_get_payload(nlh);
    struct nlattr *tb[IFLA_MAX + 1] = {};
    uint32_t ifiIdx = 0;
    struct filter_msg *msg;
    struct multi_link_info *li = NULL;

    //Ignore table 255 (local). It is updated automatically as IPs are
    //added/deleted. This was the cause of the PPP bug, the IP was removed from
    //the local table and the kernel did not know what to do! The IP and,
    //thereby, implicitly the local table is managed by removing/adding IP
    //adresses.
    //Also, multi will only use tables 1-32, so stay away from tables other than
    //those (now that we anyway dont add routes to default table)
    if(table_i->rtm_table == 255 || table_i->rtm_table > MAX_NUM_LINKS)
        return MNL_CB_OK;

    mnl_attr_parse(nlh, sizeof(*table_i), multi_link_fill_rtattr, tb);

    if(tb[RTA_OIF]){
        //Check for ignore. I have already fetched the list of all interface, so
        //any interface NOT on this list is either specified as ignore, or have
        //come up after boot and will be ignored
        ifiIdx = mnl_attr_get_u32(tb[RTA_OIF]);
        LIST_FIND_CUSTOM(li, &multi_link_links_2, next, &ifiIdx, multi_cmp_ifidx);

        if(li == NULL){
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "Not deleting route for idx %u\n", 
                    ifiIdx);
            return MNL_CB_OK;
        } else
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "Deleting route for idx %u\n", ifiIdx);

        //Clear out the whole routing table, multi will control everything!
        msg = (struct filter_msg*) malloc(nlh->nlmsg_len + 
                sizeof(TAILQ_ENTRY(filter_msg)));
        memcpy(&(msg->nlh), nlh, nlh->nlmsg_len);
        TAILQ_INSERT_TAIL(&(ip_info->ip_routes_n), msg, list_ptr);
    }

    return MNL_CB_OK;
}

static void multi_link_free_ip_info_list(struct filter_list *list){
    struct filter_msg *msg;
    while(list->tqh_first != NULL){
        msg = (struct filter_msg*) list->tqh_first;
        TAILQ_REMOVE(list, list->tqh_first, list_ptr);
        free(msg);
    }
}

/* Free the memory used by the ip_info struct */
void multi_link_free_ip_info(struct ip_info *ip_info){
    multi_link_free_ip_info_list(&(ip_info->ip_addr_n));
    multi_link_free_ip_info_list(&(ip_info->ip_rules_n));
    multi_link_free_ip_info_list(&(ip_info->ip_routes_n));
}

