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

#ifndef MULTI_LINK_CORE_H
#define MULTI_LINK_CORE_H

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <glib.h>
#include <libmnl/libmnl.h>

#include "multi_shared.h"
#include "multi_link_shared.h"

/* Reason for making these global, is that they are accsessed several times in the same "class" */
//I suspect the reason I need three sockets is that the set-function sometimes causes replies
//(when for example routes do not exist). This is why I cant use request, then
//it goes crazy because of sequence numbers. Could be solved by non-blocking
struct mnl_socket *multi_link_nl_request; //libmnl structure, new netlink communication point, used for requests
struct mnl_socket *multi_link_nl_event; //libmnl structure used only for events
struct mnl_socket *multi_link_nl_set; //limnl structure used only for setting parameters
GSList *multi_link_links; // The link module's list of all links
int32_t multi_link_dhcp_pipes[2]; // The pipe used for communication between dhcp and link module

static uint8_t multi_link_check_unique(struct multi_link_info *li, uint8_t update);
static int32_t multi_link_event_loop(struct multi_config *mc);
void *multi_link_init(void *arg);
struct multi_link_info *multi_link_create_new_link(uint8_t* dev_name, uint32_t metric); //This is also needed by filter
int32_t multi_link_filter(uint32_t seq, mnl_cb_t cb, void *arg); //Generic filter algorithm
#endif
