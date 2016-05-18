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

/* Generic includes */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/socket.h> //netlink depends on this, but does not include it?
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <assert.h>
 
/* Netlink specific */
#include <libmnl/libmnl.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>

/* iwlib. REMEMBER to update this one to include linux/if.h  */
#include <iwlib.h>

/* Network helpers */
#include <net/if.h> //Need this version of if.h because of Linux' link states
#include <net/if_arp.h>

/* Framework includes */
#include "multi_shared.h"
#include "multi_core.h"
#include "multi_link_core.h"
#include "multi_link_shared.h"
#include "multi_dhcp_main.h"
#include "multi_link_netlink.h"
#include "multi_link_filter.h"
#include "multi_common.h"
#include "multi_macros.h"
#include "multi_cmp.h"

/* See coments for where variable/function is defined */
//multi_shared
extern struct multi_shared_static_links_list multi_shared_static_links;

//multi_link_core
extern int32_t multi_link_dhcp_pipes[2];

//multi_link_netlink
extern void multi_link_configure_link(struct multi_link_info *li); 
extern void multi_link_remove_link(struct multi_link_info *li);
extern void multi_link_remove_ppp(struct multi_link_info *li);
extern void multi_link_remove_ap(struct multi_link_info *li);
extern void multi_link_get_iface_info(struct multi_link_info *li);

//multi_link_filter
extern int32_t multi_link_fill_rtattr(const struct nlattr *attr, void *data); 
extern uint8_t multi_link_check_wlan_mode(uint8_t *dev_name);
extern int32_t multi_link_filter_links(const struct nlmsghdr *nlh, void *data);
extern int32_t multi_link_filter_ipaddr(const struct nlmsghdr *nlh, void *data);
extern int32_t multi_link_filter_iprules(const struct nlmsghdr *nlh, 
        void *data);
extern int32_t multi_link_filter_iproutes(const struct nlmsghdr *nlh, 
        void *data);
extern void multi_link_free_ip_info(struct ip_info *ip_info);

//multi_dhcp_main
extern void* multi_dhcp_main(void *arg); 

int32_t multi_link_filter(uint32_t seq, mnl_cb_t cb, void *arg){
    uint8_t buf[MNL_SOCKET_BUFFER_SIZE];
    int32_t ret;
    uint32_t portid = mnl_socket_get_portid(multi_link_nl_request);

    ret = mnl_socket_recvfrom(multi_link_nl_request, buf, sizeof(buf));

    while(ret > 0){
        ret = mnl_cb_run(buf, ret, seq, portid, cb, arg);

        if(ret <= MNL_CB_STOP)
            break;

        ret = mnl_socket_recvfrom(multi_link_nl_request, buf, sizeof(buf));
    }

    return 1;
}


static void multi_link_notify_probing(int32_t probe_pipe, uint32_t ifi_idx, 
        link_state state){
    uint8_t buffer[sizeof(ifi_idx) + 1];

    buffer[0] = state;
    memcpy((buffer + 1), &ifi_idx, sizeof(ifi_idx));
    if(write(probe_pipe, buffer, sizeof(buffer)) < 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not send link notification\n"); 
    }
}

/* Check for PPP and call get_info  */
//TODO: RENAME to something more generic
static void multi_link_check_ppp(void* data, void* user_data){
    struct multi_link_info *li = (struct multi_link_info *) data;

    if(li->state == LINK_DOWN_PPP){
        multi_link_get_iface_info(li);

        //Need to do something smart here! Remover link or something!
        if(li->state != GOT_IP_PPP){
            //Need to treat this in a special way! Remove li, keep
            //li and have some sort of timeout?
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not get info for PPP link %u "
                    "(check_ppp)!\n", li->ifi_idx);
        } else{
            multi_link_remove_ppp(li);
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "Got info for PPP link %u "
                    "(check_ppp)!\n", li->ifi_idx);
        }
    } else if(li->state == LINK_DOWN_AP)
        multi_link_get_iface_info(li);
}

//Return 0 if IP is not unique
static uint8_t multi_link_check_unique(struct multi_link_info *li, 
        uint8_t update){
    struct multi_link_info *li_itr = NULL;
    uint8_t unique = 1;

    for(li_itr = multi_link_links_2.lh_first; li_itr != NULL;
            li_itr = li_itr->next.le_next){
        //Avoid comparing li with li. Locking in case a dhcp thread is about to
        //change info
        pthread_mutex_lock(&(li->state_lock));
        if(li->ifi_idx != li_itr->ifi_idx){
            if(update)
                 unique = !(li->new_cfg.address.s_addr == 
                         li_itr->new_cfg.address.s_addr);
             else
                 unique = !(li->cfg.address.s_addr == 
                         li_itr->cfg.address.s_addr);
        }

        pthread_mutex_unlock(&(li->state_lock));

        if(!unique)
            break;
    }

    return unique;
}

static void multi_link_check_link(void *data, void *user_data){
    struct multi_link_info *li = (struct multi_link_info *) data;
    struct multi_config *mc = (struct multi_config *) user_data;
    int32_t probe_pipe = mc->socket_pipe[1];

    pthread_mutex_lock(&(li->state_lock));
    if(li->state == GOT_IP_DHCP || li->state == GOT_IP_STATIC_UP || 
            li->state == GOT_IP_STATIC || li->state == GOT_IP_PPP || 
            li->state == GOT_IP_AP){
        
        /* Add routes */
        //Check for uniqueness if needed
        if(li->state == GOT_IP_DHCP && mc->unique && 
                !multi_link_check_unique(li, 0)){
            li->state = WAITING_FOR_DHCP;
            memset(&li->cfg, 0, sizeof(li->cfg));
            if(write(li->decline_pipe[1], "a", 1) < 0){
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not decline IP\n");
            }
            pthread_mutex_unlock(&(li->state_lock));
            return;
        }

        //TODO: Add error checks!
        multi_link_configure_link(li);
        if(li->state == GOT_IP_STATIC_UP){
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "IP address set for %s (iface idx %u)\n",
                    li->dev_name, li->ifi_idx);
            //Do not advertise interfaces that are only UP, they can't be used
            //yet
            li->state = LINK_UP_STATIC_IFF;
            return;
        } else
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "IP address, routes and rules set for "
                    "device %s (iface idx %u)\n", li->dev_name, li->ifi_idx);

        MULTI_DEBUG_PRINT_SYSLOG(stderr, "M U %s %u %u\n", li->dev_name, 
                li->ifi_idx, li->metric); 
        multi_link_notify_probing(probe_pipe, li->ifi_idx, LINK_UP);

		if(li->state == GOT_IP_STATIC)
			li->state = LINK_UP_STATIC;
        else if(li->state == GOT_IP_PPP)
            li->state = LINK_UP_PPP;
		else if(li->state == GOT_IP_AP)
            li->state = LINK_UP_AP;
        else{
			li->state = LINK_UP;
        }
    } else if(li->state == DHCP_IP_CHANGED){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Link %s changed IP\n", li->dev_name);

        if(mc->unique && !multi_link_check_unique(li, 1)){
            li->state = WAITING_FOR_DHCP;
            if(write(li->decline_pipe[1], "a", 1) < 0){
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not decline IP\n");
            }
            pthread_mutex_unlock(&(li->state_lock));
            return;
        }

        /* Delete and then add ip and routes */
        multi_link_notify_probing(probe_pipe, li->ifi_idx, LINK_DOWN);
        multi_link_remove_link(li);

        //Configure the new routes
        li->cfg = li->new_cfg;
        multi_link_configure_link(li);
        li->state = LINK_UP;
        multi_link_notify_probing(probe_pipe, li->ifi_idx, LINK_UP);
    } else if (li->state == DHCP_IP_INVALID){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Link %s IP is marked as invalid\n", 
                li->dev_name);
        //Delete information about link
        multi_link_remove_link(li);

        //Notify module that link is down (to an application, down and invalid
        //is the same) 
        multi_link_notify_probing(probe_pipe, li->ifi_idx, LINK_DOWN);
        li->state = LINK_INVALID;
    } else if(li->state == DHCP_FAILED){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "DHCP has failed, will clean up and "
                "remove thread!\n");
        
        /* Remove routes if link has an IP */
        if(li->cfg.address.s_addr != 0){
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "Remove routes\n");
            multi_link_remove_link(li);
        }

        li->state = DELETE_LINK;
        multi_link_notify_probing(probe_pipe, li->ifi_idx, LINK_DOWN);
    }

    pthread_mutex_unlock(&(li->state_lock));
}

/* Remove all links that have been deleted. This is only used when 
 * DHCP fails! */
static void multi_link_clean_links(){
    struct multi_link_info *li, *li_tmp;

    for(li = multi_link_links_2.lh_first; li != NULL; ){
        //I update the list while iterating, so I need to forward iterator
        li_tmp = li;
        li = li->next.le_next;

        /* No need for lock here, the state DELETE_LINK is ONLY set by this 
         * thread and DHCP thread has been cancelled */
        if(li_tmp->state == DELETE_LINK){
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "Will delete %s\n", li_tmp->dev_name);
            LIST_REMOVE(li_tmp, next);
            --multi_link_num_links;
            free(li_tmp);
        }
    }
}

struct multi_link_info *multi_link_create_new_link(uint8_t* dev_name, 
        uint32_t metric){
    struct multi_link_info *li = (struct multi_link_info *) 
        malloc(sizeof(struct multi_link_info));

    memset(li, 0, sizeof(struct multi_link_info));

    //If a link is static, use the stored metric. Otherwise, first available
    if(metric > 0){
        li->metric = metric;
        li->keep_metric = 1;
    } else {
        //Get the first available metric. I dont need to check error code, as
        //the check for num. links in modify_link ensures that there will always
        //be one metric available if the code gets here
        li->metric = ffs(~multi_shared_metrics_set);
        //ffs starts indexing from 1
        multi_shared_metrics_set ^= 1 << (li->metric - 1);
    }
    
    li->state = WAITING_FOR_DHCP;
    li->ifi_idx = if_nametoindex((char*) dev_name);
    li->write_pipe = multi_link_dhcp_pipes[1];
    memcpy(&(li->dev_name), dev_name, strlen((char*) dev_name));
    pthread_mutex_init(&(li->state_lock), NULL);

    if(pipe(li->decline_pipe) < 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not create decline pipe\n");
    }

    return li;
}

static void multi_link_delete_link(struct multi_link_info *li, 
    uint32_t probe_pipe){
    MULTI_DEBUG_PRINT_SYSLOG(stderr, "M D %s %u %u\n", li->dev_name, 
            li->ifi_idx, li->metric);

    if(li->cfg.address.s_addr != 0)
        multi_link_remove_link(li);
    
    pthread_cancel(li->dhcp_thread);
    pthread_join(li->dhcp_thread, NULL);

    LIST_REMOVE(li, next);
    --multi_link_num_links;

    if(!li->keep_metric)
        //Remember that metric is one higher than index
        multi_shared_metrics_set ^= 1 << (li->metric-1);
    
    //Should maybe be done earlier
    multi_link_notify_probing(probe_pipe, li->ifi_idx, LINK_DOWN); 

    if(li->decline_pipe[0] > 0){
        close(li->decline_pipe[0]);
        close(li->decline_pipe[1]);
    }

    free(li);
}

static void multi_link_modify_link(const struct nlmsghdr *nlh, 
        uint32_t probe_pipe, uint8_t unique){
    struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);
    struct nlattr *tb[IFLA_MAX + 1] = {};
    uint8_t iface_state = 0;
    struct multi_link_info *li = NULL;
	struct multi_link_info_static *li_static = NULL;
    pthread_attr_t detach_attr;
    uint8_t wireless_mode = 0;
    uint8_t *if_name;

    mnl_attr_parse(nlh, sizeof(*ifi), multi_link_fill_rtattr, tb);

    if (!tb[IFLA_IFNAME]) {
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Missing interface name\n");
        return;
    }

    if_name = (uint8_t*) mnl_attr_get_str(tb[IFLA_IFNAME]);

    if (strncmp(if_name, "veth", 4) ||
        ifi->ifi_type == ARPHRD_VOID ||
        (ifi->ifi_type == ARPHRD_NONE && strncmp(if_name,"wwan", 4)) ||
        ifi->ifi_type == ARPHRD_TUNNEL ||
        ifi->ifi_flags & IFF_LOOPBACK)
        return;

    if(tb[IFLA_OPERSTATE]){
        iface_state = mnl_attr_get_u8(tb[IFLA_OPERSTATE]);

        /* Check linux/Documentation/networking/operstates.txt. IFF_RUNNING 
         * wraps both UP and UNKNOWN*/
        if (ifi->ifi_flags & IFF_RUNNING){
        //IF_OPER_UP == 6, defined in linux/if.h, chaos with includes
        //if(iface_state == 6){
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "Interface %s (%u) is RUNNING, "
                    "length %u\n", if_name, ifi->ifi_index,
                    multi_link_num_links);
 
            if((wireless_mode = multi_link_check_wlan_mode(if_name)))
                if(wireless_mode == 6){
                    MULTI_DEBUG_PRINT_SYSLOG(stderr, "Interface %s is monitor, "
                            "ignoring\n", if_name);
                    return;
                }
 
            LIST_FIND_CUSTOM(li, &multi_link_links_2, next, &(ifi->ifi_index),
                    multi_cmp_ifidx);

            if(li != NULL){
                if(li->state == LINK_UP_STATIC_IFF){
                    MULTI_DEBUG_PRINT_SYSLOG(stderr, "Interface %s (idx %u) has "
                        "gone from UP to RUNNING\n", if_name, ifi->ifi_index);
                    li->state = GOT_IP_STATIC;
                } else
                    MULTI_DEBUG_PRINT_SYSLOG(stderr,"Interface %s (idx %u) has "
                        "already been seen. Ignoring event\n", if_name, 
                        ifi->ifi_index);
                return;
            }

            if(multi_link_num_links < MAX_NUM_LINKS){
                TAILQ_FIND_CUSTOM(li_static, &multi_shared_static_links,
                        list_ptr, if_name, multi_cmp_devname);

                if(li_static != NULL){
                    if(li_static->proto == PROTO_IGNORE){
                        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Ignoring %s\n", if_name);
                        return;
                    } else
                        li = multi_link_create_new_link(if_name, 
                                li_static->metric);
                } else 
                    /* Allocate a new link, add to list and start DHCP */
                    li = multi_link_create_new_link(if_name, 0);
                
                //Insert link into link list
                LIST_INSERT_HEAD(&multi_link_links_2, li, next);
                ++multi_link_num_links;

                /* Add as a case here! The check for point to point  */
                if(li_static != NULL && li_static->proto == PROTO_STATIC){
					MULTI_DEBUG_PRINT_SYSLOG(stderr, "Link %s found in static list\n", 
                            if_name);
                    li->state = GOT_IP_STATIC;
					li->cfg = li_static->cfg_static;
				} else if (ifi->ifi_type == ARPHRD_PPP){
                    /* PPP will be dealt with separatley, since they get the IP
                     * remotely by themself */
                    MULTI_DEBUG_PRINT_SYSLOG(stderr, "Link %s (%u) is PPP! state "
                            "%u %u\n", if_name, ifi->ifi_index, iface_state, 
                            IFF_RUNNING);
                    li->state = LINK_DOWN_PPP;
                    multi_link_get_iface_info(li);

                    if(li->state != GOT_IP_PPP){
                        //Need to treat this in a special way! Remove li, keep
                        //li and have some sort of timeout?
                        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not get info for PPP "
                                "link %u (first look)!\n", ifi->ifi_index);
                    } else {
                        //Clean the information that is automatically added to
                        //routing table
                        multi_link_remove_ppp(li);
                    }

                } else if(wireless_mode){ 
                    MULTI_DEBUG_PRINT_SYSLOG(stderr, "Link %s is wlan access point\n",
                            if_name);
                    li->state = LINK_DOWN_AP;
                    multi_link_get_iface_info(li);

                    //Remove the automatic route
                    multi_link_remove_ap(li);
                } else {
					pthread_attr_init(&detach_attr);
					pthread_attr_setdetachstate(&detach_attr, 
                            PTHREAD_CREATE_DETACHED);
					pthread_create(&(li->dhcp_thread), &detach_attr, 
                            multi_dhcp_main, (void *) li);
				}
            } else
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Limit reached, cannot add more links\n");
        } else if(ifi->ifi_flags & IFF_UP){ //Might replace with IF_OPER_DOWN
            //Check if interface has already been seen
            LIST_FIND_CUSTOM(li, &multi_link_links_2, next, &(ifi->ifi_index),
                    multi_cmp_ifidx);

            //Interface is already seen as UP, so clean up, no matter if static
            //or not. Static is a special case: remove routes, li from list
            //and free li
            if(li != NULL){
                //Need a generic cleanup, move the next "else" into a separate
                //function
                MULTI_DEBUG_PRINT_SYSLOG(stderr,"Interface %s (idx %u) has already "
                    "been seen as UP, will clean\n", if_name, ifi->ifi_index);
                multi_link_delete_link(li, probe_pipe);
                return;
            }

            //Check if interface is in static list
            TAILQ_FIND_CUSTOM(li_static, &multi_shared_static_links, list_ptr, 
                    if_name, multi_cmp_devname);

            if(li_static != NULL && li_static->proto == PROTO_STATIC){
                //Allocate a new link
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Link %s is UP\n", if_name);
                li = multi_link_create_new_link(if_name, li_static->metric);
                li->state = GOT_IP_STATIC_UP;
                li->cfg = li_static->cfg_static;
                LIST_INSERT_HEAD(&multi_link_links_2, li, next);
                ++multi_link_num_links;
            }
        } else {
            uint32_t dev_idx = ifi->ifi_index;
            LIST_FIND_CUSTOM(li, &multi_link_links_2, next, &dev_idx,
                    multi_cmp_ifidx);

            MULTI_DEBUG_PRINT_SYSLOG(stderr, "Interface %s (index %u) is down, "
                "length %u\n", if_name, ifi->ifi_index, 
                multi_link_num_links);

            if(li == NULL){
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not find %s (index %u), "
                    "length %u\n", if_name, ifi->ifi_index, 
                    multi_link_num_links);
            } else{
                multi_link_delete_link(li, probe_pipe);
            }
        }
    }
}

static int32_t multi_link_parse_netlink(const struct nlmsghdr *nlh, void *data){
    struct multi_config *mc = (struct multi_config*) data;

    if(nlh->nlmsg_type == RTM_NEWLINK || nlh->nlmsg_type == RTM_DELLINK)
        multi_link_modify_link(nlh, mc->socket_pipe[1], mc->unique);

    return MNL_CB_OK;
}

static void multi_link_populate_links_list(){
    //MNL_SOCKET_BUFFER_SIZE is 8k, which is the max nlmsg size (see
    //linux/netlink.h)
    uint8_t buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct rtgenmsg *rt;
    uint32_t seq;

    memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);

    //Sets room for one nlmsghdr in buffer buf
    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = time(NULL); //How will this work with event? Send 0?
    rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
    rt->rtgen_family = AF_UNSPEC; //I need all interfaces

    if(mnl_socket_sendto(multi_link_nl_request, nlh, nlh->nlmsg_len) < 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Cannot request info dump\n");
        return;
    }

    multi_link_filter(seq, multi_link_filter_links, NULL);
}

static void multi_link_del_info(struct filter_list nlmsg_list, uint16_t nlmsg_type){
    struct filter_msg *msg;
    struct nlmsghdr *nlh;
    uint32_t seq;

    for(msg = nlmsg_list.tqh_first; msg != NULL; msg = msg->list_ptr.tqe_next){
        nlh = (struct nlmsghdr*) &(msg->nlh);
        nlh->nlmsg_type = nlmsg_type;
        nlh->nlmsg_flags = NLM_F_REQUEST;
        nlh->nlmsg_seq = seq = time(NULL);

        mnl_socket_sendto(multi_link_nl_request, nlh, nlh->nlmsg_len);
    }
}

static int32_t multi_link_flush_links(){
    struct ip_info ip_info;
    uint8_t buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct rtgenmsg *rt;
    uint32_t seq;

    memset(buf, 0, MNL_SOCKET_BUFFER_SIZE);
    memset(&ip_info, 0, sizeof(ip_info));

    //Initialize list
    TAILQ_INIT(&(ip_info.ip_addr_n));
    TAILQ_INIT(&(ip_info.ip_rules_n));
    TAILQ_INIT(&(ip_info.ip_routes_n));

    //Sets room for one nlmsghdr in buffer buf
    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_GETADDR;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = time(NULL); //How will this work with event? Send 0?
    rt = mnl_nlmsg_put_extra_header(nlh, sizeof(struct rtgenmsg));
    rt->rtgen_family = AF_INET; //I need all interfaces

    //Address
    if(mnl_socket_sendto(multi_link_nl_request, nlh, nlh->nlmsg_len) < 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Cannot request address dump\n");
        return EXIT_FAILURE;
    }

    multi_link_filter(seq, multi_link_filter_ipaddr, &ip_info);

    //Rules
    nlh->nlmsg_type = RTM_GETRULE;
    if(mnl_socket_sendto(multi_link_nl_request, nlh, nlh->nlmsg_len) < 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Cannot request rules dump\n");
        return EXIT_FAILURE;
    }

    multi_link_filter(seq, multi_link_filter_iprules, &ip_info);

    //Routes
    nlh->nlmsg_type = RTM_GETROUTE;
    if(mnl_socket_sendto(multi_link_nl_request, nlh, nlh->nlmsg_len) < 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Cannot request rules dump\n");
        return EXIT_FAILURE;
    }

    multi_link_filter(seq, multi_link_filter_iproutes, &ip_info);
 
    /* Remove existing information and free memory */
    multi_link_del_info(ip_info.ip_routes_n, RTM_DELROUTE);
    multi_link_del_info(ip_info.ip_rules_n, RTM_DELRULE);
    multi_link_del_info(ip_info.ip_addr_n, RTM_DELADDR);
    multi_link_free_ip_info(&ip_info);
    return EXIT_SUCCESS;
}

static int32_t multi_link_event_loop(struct multi_config *mc){
    struct multi_link_info *li;
    pthread_attr_t detach_attr;
    uint8_t buf[MAX_PIPE_MSG_LEN];
    uint8_t mnl_buf[MNL_SOCKET_BUFFER_SIZE];
    int32_t retval, numbytes;
    uint32_t i;
    int32_t mnl_sock_event, mnl_sock_set, mnl_sock_get;
    fd_set masterfds, readfds;
    int fdmax = 0;
    struct timeval tv;

    FD_ZERO(&masterfds);
    FD_ZERO(&readfds);

    //NETLINK_ROUTE is where I want to hook into the kernel
    if(!(multi_link_nl_request = mnl_socket_open(NETLINK_ROUTE))){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not create mnl socket (request)\n");
        return EXIT_FAILURE;
    }

    if(!(multi_link_nl_set = mnl_socket_open(NETLINK_ROUTE))){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not create mnl socket (set)\n");
        return EXIT_FAILURE;
    }

    if(!(multi_link_nl_event = mnl_socket_open(NETLINK_ROUTE))){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not create mnl socket (event)\n");
        return EXIT_FAILURE;
    }

    if(mnl_socket_bind(multi_link_nl_request, 0, MNL_SOCKET_AUTOPID) < 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not bind mnl event socket\n");
        mnl_socket_close(multi_link_nl_event);
        mnl_socket_close(multi_link_nl_event);
        return EXIT_FAILURE;
    }

    if(mnl_socket_bind(multi_link_nl_set, 0, MNL_SOCKET_AUTOPID) < 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not bind mnl event socket\n");
        mnl_socket_close(multi_link_nl_event);
        mnl_socket_close(multi_link_nl_event);
        return EXIT_FAILURE;
    }

    if(mnl_socket_bind(multi_link_nl_event, RTMGRP_LINK, MNL_SOCKET_AUTOPID) 
            < 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not bind mnl event socket\n");
        mnl_socket_close(multi_link_nl_event);
        mnl_socket_close(multi_link_nl_event);
        return EXIT_FAILURE;
    }

    if(pipe(multi_link_dhcp_pipes) < 0){
        //perror("Pipe failed\n");
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Pipe failed\n");
        return EXIT_FAILURE;
    }

    /* Find interfaces that are already up, removes info and then reruns 
     * DHCP (need config) */
    multi_link_populate_links_list();

    /* Check if I have any PPP links. */
    //TODO: Give this one a better name since it is not only for PPP any more
    LIST_FOREACH_CB(&multi_link_links_2, next, multi_link_check_ppp, li, NULL);

    MULTI_DEBUG_PRINT_SYSLOG(stderr, "Done populating links list!\n");

    if(multi_link_flush_links() == EXIT_FAILURE)
        return EXIT_FAILURE;

    //Go through already seen interfaces and start DHCP as needed
    if(multi_link_num_links > 0){
        pthread_attr_init(&detach_attr);
        pthread_attr_setdetachstate(&detach_attr, PTHREAD_CREATE_DETACHED);

        for(li = multi_link_links_2.lh_first; li != NULL;
                li = li->next.le_next){
            /* Start DHCP */
            if(li->state == WAITING_FOR_DHCP){
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Starting DHCP for existing "
                        "interface %s\n", li->dev_name);
                pthread_create(&(li->dhcp_thread), &detach_attr, 
                        multi_dhcp_main, (void *) li);
            }
        }
    }

	/* Do a scan of the list here to check for links with static IP/PPP */
    LIST_FOREACH_CB(&multi_link_links_2, next, multi_link_check_link, li, mc);

    mnl_sock_event = mnl_socket_get_fd(multi_link_nl_event);
    mnl_sock_set = mnl_socket_get_fd(multi_link_nl_set);
    mnl_sock_get = mnl_socket_get_fd(multi_link_nl_request);

    FD_SET(mnl_sock_event, &masterfds); 
    fdmax = fdmax > mnl_sock_event ? fdmax : mnl_sock_event;
    FD_SET(mnl_sock_get, &masterfds);
    fdmax = fdmax > mnl_sock_get ? fdmax : mnl_sock_get;
    FD_SET(mnl_sock_set, &masterfds);
    fdmax = fdmax > mnl_sock_set ? fdmax : mnl_sock_set;
    FD_SET(multi_link_dhcp_pipes[0], &masterfds);
    fdmax = fdmax > multi_link_dhcp_pipes[0] ? fdmax : multi_link_dhcp_pipes[0];

    tv.tv_sec = 5;
    tv.tv_usec = 0;

    while(1){
        readfds = masterfds;

        retval = select(fdmax+1, &readfds, NULL, NULL, &tv);

        if(retval == 0){
            //Check for any PPP that is marked as down 
            LIST_FOREACH_CB(&multi_link_links_2, next, multi_link_check_ppp,
                    li, NULL);
            LIST_FOREACH_CB(&multi_link_links_2, next, multi_link_check_link,
                    li, mc);

            tv.tv_sec = 5;
            tv.tv_usec = 0;
            continue;
        }

        //TODO: Rewrite this so I only call the callbacks at the end, not per
        //message
        for(i=0; i<=fdmax; i++){
            if(FD_ISSET(i, &readfds)){
                if(i == mnl_sock_event){
                    numbytes = mnl_socket_recvfrom(multi_link_nl_event, 
                            mnl_buf, sizeof(mnl_buf));
                    mnl_cb_run(mnl_buf, numbytes, 0, 0, 
                            multi_link_parse_netlink, mc);
                    LIST_FOREACH_CB(&multi_link_links_2, next,
                            multi_link_check_link, li, mc);
                } else if(i == mnl_sock_set){
                    numbytes = mnl_socket_recvfrom(multi_link_nl_set, mnl_buf, 
                            sizeof(mnl_buf));
                } else if(i == mnl_sock_get){
                    numbytes = mnl_socket_recvfrom(multi_link_nl_request, 
                            mnl_buf, sizeof(mnl_buf));
                } else if(i == multi_link_dhcp_pipes[0]){
                    numbytes = read(i, buf, MAX_PIPE_MSG_LEN);
                    LIST_FOREACH_CB(&multi_link_links_2, next,
                            multi_link_check_link, li, mc);
                    multi_link_clean_links();
                }
            } 
        }
    }
}

/* TODO: Configuration */
void* multi_link_module_init(void *arg){
    struct multi_core_sync *mcs = (struct multi_core_sync *) arg;

    LIST_INIT(&multi_link_links_2);
    multi_link_num_links = 0;

    pthread_mutex_lock(&(mcs->sync_mutex));
    pthread_cond_signal(&(mcs->sync_cond));
    pthread_mutex_unlock(&(mcs->sync_mutex));
    multi_link_event_loop(mcs->mc); 

    return NULL;
}

