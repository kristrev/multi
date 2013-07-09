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

#ifndef MULTI_SHARED_H
#define MULTI_SHARED_H

#include <stdint.h>
#include <glib.h>
#include <net/if.h>
#include <sys/queue.h>
#include "multi_dhcp_common.h"

#define MAX_CFG_LEN 256
#define MAX_IP_LEN 16 //Can use inetaddrestrlen or whatever its name is
#define MAX_PORT_LEN 6
#define MAX_NUM_LINKS 32

#define TRANSPARENT 1
#define VISIBLE 0

//How IP is acquired. Either static (specified in config) or other (for example
//DHCP).
typedef enum{
    PROTO_STATIC,
    PROTO_OTHER,
    PROTO_IGNORE,
} multi_proto;

/* This struct will be filled with info and passed to MULTI */
struct multi_config{
    uint8_t cfg_file[MAX_CFG_LEN]; //Configuration file for interfaces
    int32_t socket_pipe[2];
    uint8_t unique; //Enforce unique IP addresses
};

/* Only a simple representation needed to store static links */
struct multi_link_info_static{
	uint8_t dev_name[IFNAMSIZ];
	struct multi_dhcp_config cfg_static;
    uint32_t metric;
    multi_proto proto;

    TAILQ_ENTRY(multi_link_info_static) list_ptr;
};

TAILQ_HEAD(multi_static_links_list, multi_link_info_static) 
    multi_shared_static_links_new;

//List of static interfaces
GSList* multi_shared_static_links; 

//Bitset for keeping track of metrics. Must be larger if MAX_NUM_LINKS is 
//increased
uint32_t multi_shared_metrics_set;
#endif
