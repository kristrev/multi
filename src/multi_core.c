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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <yaml.h>
#include <assert.h>

#include "multi_core.h"
#include "multi_link_core.h"
#include "multi_shared.h"
#include "multi_common.h"

extern void* multi_link_module_init(void *arg);
extern void* multi_probe_module_init(void *arg);

static uint8_t multi_core_store_address(struct multi_link_info_static *mlis, 
        uint8_t *key_data, uint8_t *value_data, uint8_t *addr_count){
    struct in_addr ipaddr;
    
    if(inet_pton(AF_INET, value_data, &ipaddr) == 0){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not convert %s (invalid parameter?)\n", 
                value_data);
        return 1;
    }

    //Only netmask and address is required, if any address information is
    //specified
    if(!strcmp(key_data, ADDRESS)){
        memcpy(&(mlis->cfg_static.address), &ipaddr, sizeof(struct in_addr));
        (*addr_count)++;
    } else if(!strcmp(key_data, NETMASK)){
        memcpy(&(mlis->cfg_static.netmask), &ipaddr, sizeof(struct in_addr));
        (*addr_count)++;
    } else if(!strcmp(key_data, GATEWAY))
        memcpy(&(mlis->cfg_static.gateway), &ipaddr, sizeof(struct in_addr));
    else {
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Found unknown parameter %s\n", key_data);
        return 1;
    }

    return 0;
}

uint8_t multi_core_parse_iface_info(struct multi_link_info_static *mlis, 
        yaml_parser_t *parser){
    yaml_event_t key, value;
    uint8_t *value_data, *key_data;
    uint8_t error = 0;
    uint32_t metric = 0;

    //Used for checking if address, netmask and gateway is provided (all
    //required if one is present)
    uint8_t addr_count = 0;
    //Proto must be set
    uint8_t proto = 0;

    while(1){
        if(!yaml_parser_parse(parser, &key)){
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not parse key\n");
            error = 1;
            break;
        }

        if(key.type == YAML_MAPPING_END_EVENT){
            yaml_event_delete(&key);
            if((addr_count > 0 && addr_count != 2) || !proto){
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Required information"
                        "(address/netmask/proto) is missing\n");
                error = 1;
            }

            break;
        } else if(key.type == YAML_SCALAR_EVENT){
            if(!yaml_parser_parse(parser, &value)){
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not parse value\n");
                error = 1;
                break;
            } else if(value.type != YAML_SCALAR_EVENT){
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Found something else than scalar\n");
                yaml_event_delete(&value);
                error = 1;
                break;
            }

            key_data = key.data.scalar.value;
            value_data = value.data.scalar.value;

            if(!strcmp(key_data, METRIC)){
                metric = atoi(value_data);
                //Metric of 0 is not allowed
                if(!metric || metric > MAX_NUM_LINKS){
                    MULTI_DEBUG_PRINT_SYSLOG(stderr, "Invalid metric\n");
                    error = 1;
                    break;
                } else {
                    //Start at index 0
                    mlis->metric = metric;

                    //Check if metric is set
                    if(multi_shared_metrics_set & (1<<(metric-1))){
                        MULTI_DEBUG_PRINT_SYSLOG(stderr, 
                                "Metric for %s is already used\n", 
                                mlis->dev_name);
                        error = 1;
                        break;
                    }

                    //The static metrics are always reserved
                    multi_shared_metrics_set ^= 1 << (metric-1);
                }
            } else if(!strcmp(key_data, PROTO)){
                proto = 1;

                if(!strcmp(value_data, "static"))
                    mlis->proto = PROTO_STATIC;
                else if(!strcmp(value_data, "other"))
                    mlis->proto = PROTO_OTHER;
                else if(!strcmp(value_data, "ignore"))
                    mlis->proto = PROTO_IGNORE;
                else{
                    MULTI_DEBUG_PRINT_SYSLOG(stderr, "Unknown protocol\n");
                    error = 1;
                    break;
                }
            } else {
                if((error = multi_core_store_address(mlis, key_data, value_data, 
                                &addr_count)))
                    break;
            }

            DEL_KEY_VALUE(key, value);
        }
    }

    return error;
}

static uint8_t multi_core_parse_config(uint8_t *cfg_filename){
    yaml_parser_t parser;
    yaml_event_t event;
    FILE *cfgfile = NULL;
    uint8_t error = 0;
    struct multi_link_info_static *mlis;
      
    //Only in use when a configuration file is present
    TAILQ_INIT(&multi_shared_static_links);

    if((cfgfile = fopen(cfg_filename, "rb")) == NULL){
        MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not open configuration file\n");
        error = 1;
        return error;
    }

    //Initialized the parser
    assert(yaml_parser_initialize(&parser));
    yaml_parser_set_input_file(&parser, cfgfile);

    while(1){
        if(!yaml_parser_parse(&parser, &event)){
            MULTI_DEBUG_PRINT_SYSLOG(stderr, "Parsing failed\n");
            error = 1;
            break;
        }

        if(event.type == YAML_STREAM_END_EVENT){
            //LibYAML might allocate memory for events and so forth. Must 
            //therefore free
            yaml_event_delete(&event);
            break;
        } else if(event.type == YAML_SCALAR_EVENT){
            if(strlen(event.data.scalar.value) > IFNAMSIZ){
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Interface name is too long\n");
                error = 1;
                break;
            }

            //The outer loop should only see scalars, which is the interface
            //names
            mlis = (struct multi_link_info_static *) 
                malloc(sizeof(struct multi_link_info_static));
            memset(mlis, 0, sizeof(*mlis));
            mlis->metric = 0;
            memcpy(mlis->dev_name, event.data.scalar.value, 
                    strlen(event.data.scalar.value) + 1);
            yaml_event_delete(&event);

            //Make sure next event is mapping!
            if(!yaml_parser_parse(&parser, &event)){
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Parsing failed\n");
                error = 1;
                break;
            } else if(event.type != YAML_MAPPING_START_EVENT){
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Configuration file is incorrect." 
                        "No information for interface\n");
                error = 1;
                break;
            }
            
            if(multi_core_parse_iface_info(mlis, &parser)){
                MULTI_DEBUG_PRINT_SYSLOG(stderr, 
                        "Parsing of configuration file failed\n");
                error = 1;
                break;
            } else {
                TAILQ_INSERT_TAIL(&multi_shared_static_links, mlis, 
                        list_ptr);
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Interface %s added to static list\n", 
                        mlis->dev_name);
            }
        }
    }

    yaml_parser_delete(&parser);
    fclose(cfgfile);

    return error;
}

/* Allocates and returns a config struct needed for multi to work */
struct multi_config* multi_core_initialize_config(uint8_t *cfg_file, 
        uint8_t unique){
    struct multi_config *mc;

    multi_shared_metrics_set = 0;
    mc = (struct multi_config *) malloc(sizeof(struct multi_config));
    memset(mc, 0, sizeof(struct multi_config));

    /* Not mandatory */
    if(cfg_file != NULL)
        //Parse configuration file
        if(multi_core_parse_config(cfg_file))
            return NULL;


    if(pipe(mc->socket_pipe) == -1){
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Failed to create pipe\n");
        return NULL;
    }
    
    //Require unique IP address or not
    mc->unique = unique;

    return mc;
}

/* This will also be started as a thread */
static void* multi_core_init(void *arg){
    struct multi_core_sync mcs;
    pthread_t link_thread, probing_thread;
    struct multi_core_sync *mcs_main = (struct multi_core_sync *) arg;

    mcs.mc = mcs_main->mc;
    pthread_cond_init(&(mcs.sync_cond), NULL);
    pthread_mutex_init(&(mcs.sync_mutex), NULL);

    /* Needs to be served config file, but ignore that for now */
    pthread_mutex_lock(&(mcs.sync_mutex));
    pthread_create(&link_thread, NULL, multi_link_module_init, &mcs);
    pthread_cond_wait(&(mcs.sync_cond), &(mcs.sync_mutex));
    pthread_mutex_unlock(&(mcs.sync_mutex));

    MULTI_DEBUG_PRINT_SYSLOG(stderr,"MULTI is ready and running\n");

    pthread_mutex_lock(&(mcs_main->sync_mutex));
    pthread_cond_signal(&(mcs_main->sync_cond));
    pthread_mutex_unlock(&(mcs_main->sync_mutex));

    pthread_join(link_thread, NULL);

    return NULL;
}

/* Starts the multi thread */
pthread_t multi_start(struct multi_config *mc){
    pthread_t multi_thread;
    struct multi_core_sync mcs;

    mcs.mc = mc;
    pthread_cond_init(&(mcs.sync_cond), NULL);
    pthread_mutex_init(&(mcs.sync_mutex), NULL);

    /* Start MULTI */
    pthread_mutex_lock(&(mcs.sync_mutex));
    pthread_create(&multi_thread, NULL, multi_core_init, &mcs);
    pthread_cond_wait(&(mcs.sync_cond), &(mcs.sync_mutex));
    pthread_mutex_unlock(&(mcs.sync_mutex));

    return multi_thread;
}
