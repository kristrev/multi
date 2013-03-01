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

#include <glib.h>
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

#include "multi_shared.h"
#include "multi_link_core.h"
#include "multi_link_filter.h"
#include "multi_link_shared.h"

extern GSList *multi_link_static_links;
extern GSList *multi_link_links;
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

    if((wlan_sock = iw_sockets_open()) > 0)
        //This can be optimised, MODE is just a normal ioctl
        if(!iw_get_basic_config(wlan_sock, dev_name, &wcfg))
            if(wcfg.mode == 3 || wcfg.mode == 6)
                return wcfg.mode;

    return 0;
}

/* The compare functions used by the different filters */
static gint multi_link_cmp_ifidx(gconstpointer a, gconstpointer b){
    struct multi_link_info *li = (struct multi_link_info *) a;
    struct ifaddrmsg *ifa = (struct ifaddrmsg *) b;

    //Ignore PPP interfaces, as they will not be flushed!
    if((li->state != GOT_IP_PPP && li->state != GOT_IP_AP) && li->ifi_idx == 
            ifa->ifa_index)
        return 0;
}

static gint multi_link_cmp_ipaddr(gconstpointer a, gconstpointer b){
    struct multi_link_info *li = (struct multi_link_info *) a;
    uint32_t *ip_addr_cmp = (uint32_t *) b;

    MULTI_DEBUG_PRINT(stderr, "Comparing %u with %u\n", li->cfg.address.s_addr, 
            *ip_addr_cmp);

    //Comparing IP address will of course NOT work. This function is only used
    //on flush, which is done BEFORE DHCP is run!
    if(li->cfg.address.s_addr == *ip_addr_cmp)
        return 0;
}

static gint multi_link_cmp_oif(gconstpointer a, gconstpointer b){
    struct multi_link_info *li = (struct multi_link_info *) a;
    uint32_t *oif = (uint32_t *) b;

    if(li->ifi_idx == *oif)
        return 0;
}

static gint multi_link_cmp_devname(gconstpointer a, gconstpointer b){
	struct multi_link_info_static *li = (struct multi_link_info_static *) a;
	uint8_t *dev_name = (uint8_t *) b;

	if(!g_strcmp0(li->dev_name, dev_name))
		return 0;
	else
		return 1;
}

int32_t multi_link_filter_links(const struct nlmsghdr *nlh, void *data){
    //nlattr is the generic form of rtattr
    struct nlattr *tb[IFLA_MAX + 1] = {};
    struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);
    uint8_t devname[IFNAMSIZ];
    uint8_t operstate;
    struct multi_link_info *li;
	struct multi_link_info_static *li_static = NULL;
	GSList *li_static_tmp;
    uint8_t wireless_mode = 0;

    /* Tunneling interfaces have no ARP header, so they can be ignored, 
     * as well as loopback. See linux/if_arp.h for different definitions */
    if(ifi->ifi_type == ARPHRD_VOID || ifi->ifi_type == ARPHRD_NONE || 
            ifi->ifi_flags & IFF_LOOPBACK)
        return MNL_CB_OK;

    //Check for WLAN
    if_indextoname(ifi->ifi_index, devname);

    if((wireless_mode = multi_link_check_wlan_mode(devname)))
        if(wireless_mode == 6){
            MULTI_DEBUG_PRINT(stderr, "Interface %s is wireless monitor, "
                    "ignoring\n", devname);
            return MNL_CB_OK;
        }

    //Ignore incoming interfaces too
    if(strstr(devname, "ifb"))
        return MNL_CB_OK;

    mnl_attr_parse(nlh, sizeof(*ifi), multi_link_fill_rtattr, tb);

    if(tb[IFLA_OPERSTATE]){
        operstate = mnl_attr_get_u8(tb[IFLA_OPERSTATE]);

        //Interface is up, do normal operation
        if(ifi->ifi_flags & IFF_RUNNING){
            //Assume that there is initially always room for every link. Maybe
            //change?
            if((li_static_tmp = g_slist_find_custom(multi_shared_static_links, 
                            devname, multi_link_cmp_devname))){
                li_static = li_static_tmp->data;
                li = multi_link_create_new_link(devname, li_static->metric);
            } else 
                /* Allocate a new link, add to list and start DHCP */
                li = multi_link_create_new_link(devname, 0);

			/* If link exists in static link list, set link to GOT_STATIC */
			if(li_static != NULL && li_static->proto == PROTO_STATIC){
				MULTI_DEBUG_PRINT(stderr, "Link %s was found in static list\n", 
                        devname);
				li_static = li_static_tmp->data;
				li->state = GOT_IP_STATIC;
				li->cfg = li_static->cfg_static;
			} else if(ifi->ifi_type == ARPHRD_PPP){
                /* PPP will be dealt with separatley, since they get the IP
                 * remotely by themself */
                MULTI_DEBUG_PRINT(stderr, "Link %s is PPP!\n", devname);
                li->state = LINK_DOWN_PPP;
            } else if(wireless_mode == 3){
                MULTI_DEBUG_PRINT(stderr, "Link %s is wireless access point\n", 
                        devname);
                li->state = LINK_DOWN_AP;                
            } else
                MULTI_DEBUG_PRINT(stderr, "Found link %s\n", devname);

            //The order in which links are stored in this list is not important
            multi_link_links = g_slist_prepend(multi_link_links, (gpointer) li); 

        }
    }

    return MNL_CB_OK;
}

int32_t multi_link_filter_ipaddr(const struct nlmsghdr *nlh, void *data){
    struct ip_info *ip_info = (struct ip_info *) data;
    struct ifaddrmsg *ifa = mnl_nlmsg_get_payload(nlh);
    struct nlattr *tb[IFLA_MAX + 1] = {};
    struct nlmsghdr *nlh_tmp;
    uint32_t ipaddr;

    if(g_slist_find_custom(multi_link_links, ifa, multi_link_cmp_ifidx)){
        //Copy the nlmsg, as I will recycle it later when I delete everything!
        nlh_tmp = (struct nlmsghdr *) malloc(nlh->nlmsg_len);
        memcpy(nlh_tmp, nlh, nlh->nlmsg_len);
        ip_info->ip_addr_n = g_slist_append(ip_info->ip_addr_n, 
                (gpointer) nlh_tmp);

        mnl_attr_parse(nlh, sizeof(*ifa), multi_link_fill_rtattr, tb);

        if(tb[IFA_LOCAL]){
            ipaddr = mnl_attr_get_u32(tb[IFA_LOCAL]); 
            ip_info->ip_addr = g_slist_append(ip_info->ip_addr, 
                    GUINT_TO_POINTER(ipaddr));
        }
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
        inet_ntop(AF_INET, &(sa.sin_addr), addr_buf, INET_ADDRSTRLEN);
        MULTI_DEBUG_PRINT(stderr, "Local address: %s \n", addr_buf);

        sa.sin_family = AF_INET;
        sa.sin_addr = li->cfg.broadcast;
        inet_ntop(AF_INET, &(sa.sin_addr), addr_buf, INET_ADDRSTRLEN);
        MULTI_DEBUG_PRINT(stderr, "Remote address: %s\n", addr_buf);
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
        inet_ntop(AF_INET, &(sa.sin_addr), addr_buf, INET_ADDRSTRLEN);
        MULTI_DEBUG_PRINT(stderr, "Local address: %s \n", addr_buf);

        sa.sin_family = AF_INET;
        sa.sin_addr = li->cfg.netmask;
        inet_ntop(AF_INET, &(sa.sin_addr), addr_buf, INET_ADDRSTRLEN);
        MULTI_DEBUG_PRINT(stderr, "Netmask: %s\n", addr_buf);
    }

    return MNL_CB_OK;
}

/* Get the ip rules that belong to the current interfaces */
int32_t multi_link_filter_iprules(const struct nlmsghdr *nlh, void *data){
    struct ip_info *ip_info = (struct ip_info *) data;
    struct rtmsg *rt = mnl_nlmsg_get_payload(nlh);
    struct nlattr *tb[IFLA_MAX + 1] = {};
    uint32_t ipaddr = 0;
    struct nlmsghdr *nlh_tmp;

    mnl_attr_parse(nlh, sizeof(*rt), multi_link_fill_rtattr, tb);

    if(!(tb[FRA_SRC]))
        return MNL_CB_OK;

    ipaddr = mnl_attr_get_u32(tb[FRA_SRC]);

    //Delete ANY rule which does not point to one of the default tables
    if(rt->rtm_table > 0 && rt->rtm_table < 253){
        MULTI_DEBUG_PRINT(stderr,  "Added rule with id %u to flush list\n", 
                mnl_attr_get_u32(tb[FRA_PRIORITY]));

        /* Add the rule nlmsg to list */
        nlh_tmp = (struct nlmsghdr *) malloc(nlh->nlmsg_len);
        memcpy(nlh_tmp, nlh, nlh->nlmsg_len);
        ip_info->ip_rules_n = g_slist_append(ip_info->ip_rules_n, 
                (gpointer) nlh_tmp);
    }

    return MNL_CB_OK;
}

int32_t multi_link_filter_iproutes(const struct nlmsghdr *nlh, void *data){
    struct ip_info *ip_info = (struct ip_info *) data;
    struct rtmsg *table_i = mnl_nlmsg_get_payload(nlh);
    struct nlattr *tb[IFLA_MAX + 1] = {};
    uint32_t oif;
    struct nlmsghdr *nlh_tmp;

    //Ignore table 255 (local). It is updated automatically as IPs are
    //added/deleted. This was the cause of the PPP bug, the IP was removed from
    //the local table and the kernel did not know what to do! The IP and,
    //thereby, implicitly the local table is managed by removing/adding IP
    //adresses.
    if(table_i->rtm_table == 255)
        return MNL_CB_OK;

    mnl_attr_parse(nlh, sizeof(*table_i), multi_link_fill_rtattr, tb);

    if(tb[RTA_OIF]){
        oif = mnl_attr_get_u32(tb[RTA_OIF]);

        //Clear out the whole routing table, multi will control everything!
        nlh_tmp = (struct nlmsghdr *) malloc(nlh->nlmsg_len);
        memcpy(nlh_tmp, nlh, nlh->nlmsg_len);
        ip_info->ip_routes_n = g_slist_append(ip_info->ip_routes_n, 
                (gpointer) nlh_tmp);
    }

    return MNL_CB_OK;
}

static void multi_link_free_ip_info_list(GSList *list){
    GSList *list_itr = list;
    GSList *list_old = NULL;

    while(list_itr){
        list_old = list_itr;
        list_itr = g_slist_next(list_itr);
        free(list_old->data);
    }
}

/* Free the memory used by the ip_info struct */
void multi_link_free_ip_info(struct ip_info *ip_info){
    multi_link_free_ip_info_list(ip_info->ip_addr_n);
    multi_link_free_ip_info_list(ip_info->ip_rules_n);
    multi_link_free_ip_info_list(ip_info->ip_routes_n);

    /* Free lists */
    g_slist_free(ip_info->ip_addr);
    g_slist_free(ip_info->ip_addr_n);
    g_slist_free(ip_info->ip_rules_n);
    g_slist_free(ip_info->ip_routes_n);

}

