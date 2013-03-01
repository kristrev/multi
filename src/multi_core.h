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

#ifndef MULTI_CORE_H
#define MULTI_CORE_H

#include <stdint.h>
#include <pthread.h>

#include "multi_shared.h"

//Current valid configuration options
#define ADDRESS "address"
#define NETMASK "netmask"
#define GATEWAY "gateway"
#define METRIC "metric"
#define PROTO "proto"

//Macro for freeing memory allocated to store a pair
#define DEL_KEY_VALUE(key, value) \
    yaml_event_delete(&key); \
    yaml_event_delete(&value);

/* Internal thread used to synchronize thread startup */
struct multi_core_sync{
    struct multi_config *mc; 
    pthread_mutex_t sync_mutex;
    pthread_cond_t sync_cond;
};

struct multi_config* multi_core_initialize_config(uint8_t *cfg_file, 
        uint8_t unique);
int32_t multi_core_send(int32_t sock_fd, uint8_t *buf, int32_t numbytes);
pthread_t multi_start(struct multi_config *mc);
#endif
