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

#ifndef MULTI_DHCP_NETWORK_H
#define MULTI_DHCP_NETWORK_H

#include "multi_dhcp_common.h"
#include "multi_link_shared.h"

#include <netinet/in.h>
#include <stdint.h>

/* Used to send messages over the raw socket. If broadcast is set to one, then from_ip is src ip. Otherwise,
 * src is gathered from client address in the dhcp msg (case only relevant after succesful BIND) */
int32_t multi_dhcp_snd_msg_raw(int sock, struct in_addr from_ip, int from_if, struct multi_dhcp_message *msg, uint8_t broadcast);

/* Send a message unicast. Used to renew a lease, as the initial messages are sent directly to the server */
int32_t multi_dhcp_snd_msg_udp(int sock, struct in_addr *to, struct multi_dhcp_message *msg);

/* IPv4 checksumming */
static uint16_t multi_dhcp_in_cksum(const uint16_t *addr, register int len, uint16_t csum);

/* Receives DHCP messages. The message is stored in ms and function returns 0 on success, -1 otherwise */
int32_t multi_dhcp_recv_msg(struct multi_dhcp_info *di, struct multi_dhcp_message *dhcp_msg);

/* Creates RAW and UDP socket. In order to avoid redundant calls, di is included to store the interface index and mac-addr */
int32_t multi_dhcp_create_raw_socket(struct multi_link_info *li, struct multi_dhcp_info *di);
int multi_dhcp_create_udp_socket(struct multi_link_info *li);

/* Helter that currently pushes one byte through the pipe to notify the link module. Will maybe contain more info in future versions */
void multi_dhcp_notify_link_module(int32_t pipe_fd);

#endif
