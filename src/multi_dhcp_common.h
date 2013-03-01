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

#ifndef MULTI_DHCP_COMMON_H
#define MULTI_DHCP_COMMON_H

#include "multi_dhcp_constants.h"

#include <netinet/in.h>
#include <stdint.h>

/* DHCP's magic cookie */
static const uint8_t multi_dhcp_vendcookie[] = { 99, 130, 83, 99 };

typedef enum {
  DHCP_OVERLOAD_NONE,
  DHCP_OVERLOAD_FILE,
  DHCP_OVERLOAD_SNAME,
  DHCP_OVERLOAD_BOTH
} multi_dhcp_overload_opts;

typedef enum{
    INIT,
    INIT_REBOOT,
    SELECTING,
    REQUESTING,
    BOUND,
    REBOOTING,
    RENEWING,
    REBINDING,
    DECLINE

} multi_dhcp_state;

/* config received from server, mostly via options */
struct multi_dhcp_config {
  /* timestamp we received the message */
  struct timeval recvtime;

  /* server address */
  struct in_addr dhcpd_addr;

  /* parsed options */
  struct in_addr address;
  struct in_addr netmask;
  struct in_addr broadcast;

  struct in_addr gateway;

  struct in_addr dns[MAXOPTS];
  unsigned short dns_num;

  char hostname[HOST_NAME_MAX];
  char domainname[HOST_NAME_MAX];

  unsigned int t1;
  unsigned int t2;
  unsigned int lease;

  char dhcpmsgtype;
};

struct multi_dhcp_message {
  uint8_t *pos, *last;
  multi_dhcp_overload_opts overload, currentblock;

  /* embedded DHCP message */
  uint8_t op;
  uint8_t htype;
  uint8_t hlen;
  uint8_t hops;
  uint32_t xid;
  uint16_t secs;
  uint16_t flags;
  uint32_t ciaddr;
  uint32_t yiaddr;
  uint32_t siaddr;
  uint32_t giaddr;
  uint8_t chaddr[16];
  uint8_t sname[64];
  uint8_t file[128];
  uint8_t options[MAX_OPT_LEN];
} __attribute__((packed));

struct multi_dhcp_info{
    uint32_t xid;
    struct sockaddr mac_addr;
    uint32_t ifidx;
    uint32_t raw_sock;
    uint32_t udp_sock; //Used for unicast-messages
    multi_dhcp_state state;
    struct multi_dhcp_config cfg;

    /* Used for the different timeouts */
    uint32_t req_sent_time;
    uint32_t req_retrans; //All these are expressed as absolute values
    uint32_t t1;
    uint32_t t2;
    uint32_t lease;
    uint8_t retrans_count;
    uint8_t output_timer; //Says wheter or not a NEW timer event has started, to make output nicer
};

#endif
