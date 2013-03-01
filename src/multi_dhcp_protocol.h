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

#ifndef MULTI_DHCP_PROTOCOL_H
#define MULTI_DHCP_PROTOCOL_H

#include "multi_dhcp_common.h"
#include "multi_dhcp_constants.h"
#include "multi_link_shared.h"

#include <stdint.h>

/* The options I am interested in (domain is just my domain, 
 * for example simula.no) */
static char multi_dhcp_optlist[] = { 
    BOOTP_OPTION_NETMASK, 
    BOOTP_OPTION_GATEWAY, 
    BOOTP_OPTION_DNS,
	BOOTP_OPTION_HOSTNAME, 
    BOOTP_OPTION_DOMAIN, 
    BOOTP_OPTION_BROADCAST,
	DHCP_OPTION_LEASE, 
    DHCP_OPTION_T1, 
    DHCP_OPTION_T2 
};

/* Creates a dhcp msg and sends it over the network through the interface 
 * specified by di */
int32_t multi_dhcp_create_dhcp_msg(struct multi_dhcp_info *di);

/* Parses the options in msg and stores them in cfg */
static void multi_dhcp_parse_options(struct multi_dhcp_message *msg, 
        struct multi_dhcp_config *cfg);

/* Parses the message and stores relevant information in di */
void multi_dhcp_parse_dhcp_msg(struct multi_dhcp_info *di, 
        struct multi_dhcp_message *dm, struct multi_link_info *li);

#endif
