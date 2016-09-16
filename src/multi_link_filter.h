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

#ifndef MULTI_LINK_FILTER_H
#define MULTI_LINK_FILTER_H

#include <stdint.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <sys/queue.h>

struct filter_msg{
    //TODO: Union with nlh and uint32 for the address
    TAILQ_ENTRY(filter_msg) list_ptr;
    struct nlmsghdr nlh;
};

TAILQ_HEAD(filter_list, filter_msg);

/* Helper struct to keep the different lists of information needed to 
 * configure a system where interfaces are already up  */
//TODO: Use pointers instead?
struct ip_info{
    struct filter_list ip_addr_n; //The nlmsgs, will be used to delete ip addresses
    struct filter_list ip_rules_n; //The netlink messages containing the rules
    struct filter_list ip_routes_n; //The table ID
    void *data; //Pointer that can be used to store private data
};

//Helper function for filling in rtattr
int32_t multi_link_fill_rtattr(const struct nlattr *attr, void *data); 
uint8_t multi_link_check_wlan_mode(uint8_t *dev_name);
int32_t multi_link_filter_links(const struct nlmsghdr *nlh, void *data);
int32_t multi_link_filter_ipaddr(const struct nlmsghdr *nlh, void *data);
int32_t multi_link_filter_iprules(const struct nlmsghdr *nlh, void *data);
int32_t multi_link_filter_iprules_addr(const struct nlmsghdr *nlh, void *data);
int32_t multi_link_filter_iproutes(const struct nlmsghdr *nlh, void *arg);
int32_t multi_link_filter_ppp(const struct nlmsghdr *nlh, void *data);
int32_t multi_link_filter_ap(const struct nlmsghdr *nlh, void *data);
void multi_link_free_ip_info(struct ip_info *ip_info);

#endif
