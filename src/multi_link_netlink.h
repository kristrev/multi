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

#ifndef MULTI_LINK_NETLINK_H
#define MULTI_LINK_NETLINK_H

#include "multi_link_shared.h"

#define ADDR_RULE_PRIO  10000
#define NW_RULE_PRIO    20000
#define DEF_RULE_PRIO   91000

/* Configure IP + routes + rule */
void multi_link_configure_link(struct multi_link_info *li);

/* Remote IP + routes + rule */
void multi_link_remove_link(struct multi_link_info *li);

/* Remove the info added automatically by pppd/ifconfig (for ap)  */
void multi_link_remove_ppp(struct multi_link_info *li);
extern void multi_link_remove_ap(struct multi_link_info *li);

/* Get all the registred information about a PPP interface and store it in
 * config!  */
void multi_link_get_iface_info(struct multi_link_info *li);

#endif
