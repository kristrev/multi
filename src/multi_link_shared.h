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

#ifndef MULTI_LINK_SHARED_H
#define MULTI_LINK_SHARED_H

#include <stdint.h>
#include <glib.h>
#include <pthread.h>
#include <net/if.h>

#include "multi_dhcp_common.h"
#include "multi_common.h"

#define MAX_PIPE_MSG_LEN 10 //Can be useful later on, if the pipe is used for more useful information

struct multi_link_info{
    int32_t write_pipe; //Used by the DHCP-thread to signal link thread. Used for notification, not for identification. DHCP updates the state of this link (if used)!
    struct multi_dhcp_config cfg, new_cfg; //Store the configuration (new cfg is used when config changes)
    uint8_t dev_name[IFNAMSIZ]; //Name of interface to perform DHCP on
    link_state state; //Indicates which state the link is in, used by DHCP and Link module to decide on action
    uint32_t ifi_idx; //Convenience, the interface index is used so many times that it makes sense to put it here
    uint32_t metric; //Routing table metric
    uint8_t keep_metric; //Set for config entries with the metric set. The metric is assumed to be persistent

    int32_t decline_pipe[2]; //Used to instruct DHCP client that the IP should be declined
    pthread_t dhcp_thread;
    GStaticRWLock state_lock; //This might not have to be locked at all (can leave with some level of instability), but have rwlock for now
};

#endif
