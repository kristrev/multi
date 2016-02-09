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

#include "multi_dhcp_common.h"
#include "multi_dhcp_constants.h"
#include "multi_dhcp_main.h"
#include "multi_dhcp_protocol.h"
#include "multi_dhcp_network.h"
#include "multi_link_shared.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>

extern void multi_dhcp_create_dhcp_msg(struct multi_dhcp_info *di);
extern int32_t multi_dhcp_recv_msg(struct multi_dhcp_info *di, 
        struct multi_dhcp_message *dhcp_msg);
extern void multi_dhcp_parse_dhcp_msg(struct multi_dhcp_info *di, 
        struct multi_dhcp_message *dm, struct multi_link_info *li);

static void multi_dhcp_setup_random() {
    int32_t fd;
    uint32_t seed = time(NULL);

    fd = open("/dev/urandom", O_RDONLY);

    if (fd != -1) {
        read(fd, &seed, sizeof(seed));
        close(fd);
    }

    srand(seed);
}

/* This is the state machine for timeouts */
static void multi_dhcp_event_loop(struct multi_dhcp_info *di, 
        struct multi_link_info *li){
    fd_set master, read_fds;
    uint32_t fdmax;
    int32_t retval;
    struct timeval tv;
    uint32_t next_to, t_now; //next_to stores the next timeout, while t_now is used as the base value (all times are absolute)
    char buffer[1500]; //The DHCP-client never cares about data received on the UDP socket
    struct multi_dhcp_message dhcp_msg;

    /* Initialize select */
    FD_ZERO(&master);
    FD_ZERO(&read_fds);
    FD_SET(di->raw_sock, &master);
    FD_SET(di->udp_sock, &master);
    FD_SET(li->decline_pipe[0], &master);
    fdmax = di->raw_sock > di->udp_sock ? di->raw_sock : di->udp_sock;
    fdmax = fdmax > li->decline_pipe[0] ? fdmax : li->decline_pipe[0];

    /* Create and send the initial DHCP Discover */
    multi_dhcp_create_dhcp_msg(di);

    while (1){
        read_fds = master;
        //Used as offset for the time values, since everything is absolute 
        //values
        t_now = time(NULL); 

        /* These three states are simple, as there is no competing deadline 
         * (they are all first step in a state change) */
        if(di->state == SELECTING || di->state == REQUESTING || 
                di->state == REBOOTING || di->state == DECLINE){
            next_to = di->req_retrans;
        } else if (di->state == BOUND) {
            next_to = di->t1;
        } else if (di->state == RENEWING) {
            /* For both renewing and rebinding, there is a competing timeout */
            next_to = di->req_retrans < di->t2 ? di->req_retrans : di->t2;
        } else if (di->state == REBINDING){
            next_to = di->req_retrans < di->lease ? di->req_retrans : di->lease;
        }

        /* INIT allows packet should be sent ASAP (can get in INIT after for 
         * example NAK), so no timer */
        if(di->state != INIT && t_now < next_to){
            /* Which timeout to use is derived from the current DHCP state. 
             * All values are absolute, so subtract time now */
            tv.tv_sec = next_to - t_now;
            tv.tv_usec = 0;

            if(di->output_timer){
                MULTI_DEBUG_PRINT_SYSLOG(stderr,"Next timeout will expire in %u sec "
                        "on interface %s (iface idx %u)\n", 
                        (uint32_t) tv.tv_sec, li->dev_name, li->ifi_idx);
                di->output_timer = 0;
            }

            retval = select(fdmax + 1, &read_fds, NULL, NULL, &tv);
        } else {
            //If the timer is larger than or equal to timeout, means that 
            //timeout has occured
            retval = 0;
        }

        //Decline requires me to wait 10 seconds, then return to INIT. INIT
        //normally has no timeout. Thus, I have to sleep, then update state.
        if(di->state == DECLINE)
            di->state = INIT;

        if(retval == 0){
            di->retrans_count++; //Start at 0, to get expected behavior

            if(di->retrans_count > REBOOTING_THRESHOLD){
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Could not get a reply after %u" 
                        "timeouts, falling back to INIT/REBOOTING for interface" 
                        "%s\n", di->retrans_count, li->dev_name);
               
               //Try reboot, so I at least will have higher chance of keeping IP 
                di->state = (di->state == BOUND || di->state == RENEWING) ? 
                    REBOOTING : INIT;
                di->retrans_count = 0;
                di->req_sent_time = 0;
                multi_dhcp_create_dhcp_msg(di);
                continue;
            }

            switch(di->state){
                case INIT:
                case SELECTING:
                case REQUESTING:
                case REBOOTING:
                    /* If REBOOTING fails a sufficient number of times,  */
                    if(di->retrans_count > REBOOTING_THRESHOLD){
                        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Rebooting threshold reached,"
                                "going back to INIT.\n");
                        di->state = INIT;
                        di->retrans_count = 0;
                        di->req_sent_time = 0;
                    }
                    multi_dhcp_create_dhcp_msg(di);
                    break;
                case BOUND:
                case RENEWING:
                    t_now = time(NULL);

                    if(t_now >= di->t2){
                        MULTI_DEBUG_PRINT_SYSLOG(stderr,"T2 has expired for %s (iface" 
                                "idx %u)\n", li->dev_name, li->ifi_idx);
                        di->retrans_count = 0; //Switch state
                        di->state = REBINDING;
                    }

                    multi_dhcp_create_dhcp_msg(di);
                    break;
                case REBINDING:
                    /* Need a check for lease, if lease has expired */
                    if(t_now >= di->lease){
                        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Lease has expired for %s" 
                                "(iface idx %u)\n", li->dev_name, li->ifi_idx);
                        di->retrans_count = 0;
                        di->req_sent_time = 0;
                        di->state = INIT;

                        /* Update link state and notify link module  */
                        pthread_mutex_lock(&(li->state_lock));
                        //Only send if seend once
                        if(li->state != DHCP_IP_INVALID && li->state 
                                != LINK_INVALID){
                            li->state = DHCP_IP_INVALID;
                            multi_dhcp_notify_link_module(li->write_pipe);
                        }
                        pthread_mutex_unlock(&(li->state_lock));
                    }

                    multi_dhcp_create_dhcp_msg(di);
                default:
                    break;
            }
        } else {
            if(FD_ISSET(di->raw_sock, &read_fds)){
                memset(&dhcp_msg, 0, sizeof(dhcp_msg));
                
                multi_dhcp_recv_msg(di, &dhcp_msg);
                multi_dhcp_parse_dhcp_msg(di, &dhcp_msg, li);
            } else if(FD_ISSET(di->udp_sock, &read_fds)){
                recv(di->udp_sock, buffer, 1500, 0);
            } else if(FD_ISSET(li->decline_pipe[0], &read_fds)){
                read(li->decline_pipe[0], buffer, 1500);
                MULTI_DEBUG_PRINT_SYSLOG(stderr, "Must decline IP for %s\n", 
                        li->dev_name);
                di->state = DECLINE;
                multi_dhcp_create_dhcp_msg(di);
            }
        }
    }
}

static void multi_dhcp_cleanup(void *arg){
    struct multi_dhcp_info *di = (struct multi_dhcp_info *) arg;

    /* Send release */

    /* Close sockets */
	if(di->raw_sock > 0)
	    close(di->raw_sock);

	if(di->udp_sock > 0)
	    close(di->udp_sock);

    MULTI_DEBUG_PRINT_SYSLOG(stderr,"Finished DHCP cleanup for interface with index" 
            "%u. Sent RELEASE and closed sockets %u and %u.\n", di->ifidx, 
            di->raw_sock, di->udp_sock);
}

void* multi_dhcp_main(void *arg){
    struct multi_link_info *li = (struct multi_link_info *) arg;
    struct multi_dhcp_info di;

    /* Currently, this thread can be cancelled at any time */
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    pthread_cleanup_push(multi_dhcp_cleanup, &di);

    /* Initializes the random number generator */
    multi_dhcp_setup_random();

    memset(&di, 0, sizeof(di));
    
    if(li->state == REBOOT_DHCP){
        di.state = INIT_REBOOT;
        di.cfg.address = li->cfg.address;
    } else {
        di.state = INIT;
    }
    
    //The transaction ID is a random number chosen by the client
    di.xid = rand(); 
    di.output_timer = 0;
    
    if((di.raw_sock = multi_dhcp_create_raw_socket(li, &di)) == -1){
        return;
    }

    if((di.udp_sock = multi_dhcp_create_udp_socket(li)) == -1){
        return;
    }
   
    if(di.state == REBOOT_DHCP){
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Waiting for DHCP REBOOT on interface %s " 
                "(iface idx %u). RAW socket: %u UDP socket: %u\n", li->dev_name,
                li->ifi_idx, di.raw_sock, di.udp_sock);
    } else{
        MULTI_DEBUG_PRINT_SYSLOG(stderr,"Waiting for DHCP on interface %s (iface idx " 
                "%u). RAW socket: %u UDP socket: %u\n", li->dev_name, 
                li->ifi_idx, di.raw_sock, di.udp_sock);
    }

    multi_dhcp_event_loop(&di, li);

    pthread_cleanup_pop(1); /* Cleanup when failed too */
    pthread_exit(NULL);
}
