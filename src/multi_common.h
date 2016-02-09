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

#ifndef MULTI_COMMON_H
#define MULTI_COMMON_H

#include <syslog.h>

#define MAX_BUFSIZE 1500

typedef enum{
    //Initial state, link cannot be used (can still be up and running)
    LINK_DOWN=0,
    //Link is ready and can be used
    LINK_UP, 
    //Signal that information about the PPP interface must be collected. Needed to restore state, because of non-working nested wilddump/filter
    LINK_DOWN_PPP, 
    //Signal that information about a wireless ap interface must be collected
    LINK_DOWN_AP,
    //Link has lost its current IP address and cant be used
    LINK_INVALID, 
    //If DHCP is to be used on this link, indicates that link is waiting for DHCP to finish
    WAITING_FOR_DHCP, 
    //DHCP has finished successfully, info store in cfg and the main thread will configure interface
    GOT_IP_DHCP, 
    //Static IP, interface is up, but not running (so no cable attached)
    GOT_IP_STATIC_UP,
	//Has a static IP address
    GOT_IP_STATIC, 
    //This is a PPP interface, which will be given an IP automaticually
    GOT_IP_PPP, 
    //Got the information about the wireless access point interface
    GOT_IP_AP, 
    //DHCP failed, the application will ignore this interface forever (for now). 
    //TODO: Decide if it should be freed.
    DHCP_FAILED, 
    //DHCP got a new IP after a RENEW/REBIND, must first flush then add new info
    DHCP_IP_CHANGED, 
    //DHCP lease has expired and a new IP has not been received. This does not 
    //mean that the interface is down, but it cant be used!
    DHCP_IP_INVALID, 
    //Interface is up, but not active (i.e., no cable)
    LINK_UP_STATIC_IFF,
	//Link is up and with a static IP (used to avoid seg fault when link goes 
    //down!)
    LINK_UP_STATIC, 
    //Same as above, but for PPP
    LINK_UP_PPP, 
    //Access point is up and configured
    LINK_UP_AP, 
    //Interface has previously been allocated an IP, try to reuse that one
    REBOOT_DHCP, 
    //The link module has marked this link for deletion (needed because 
    //g_slist_foreach is not safe)
    DELETE_LINK 
} link_state;

#define MULTI_LOG_PREFIX "[%.2d:%.2d:%.2d %.2d/%.2d/%d]: "
#define MULTI_DEBUG_PRINT2(fd, ...){fprintf(fd, __VA_ARGS__);fflush(fd);}
#define MULTI_DEBUG_SYSLOG(priority, ...){syslog(LOG_MAKEPRI(LOG_DAEMON, priority), __VA_ARGS__);}
//The ## is there so that I dont have to fake an argument when I use the macro
//on string without arguments!
#define MULTI_DEBUG_PRINT(fd, _fmt, ...) \
    do { \
    time_t rawtime; \
    struct tm *curtime; \
    time(&rawtime); \
    curtime = gmtime(&rawtime); \
    MULTI_DEBUG_PRINT2(fd, MULTI_LOG_PREFIX _fmt, curtime->tm_hour, \
        curtime->tm_min, curtime->tm_sec, curtime->tm_mday, \
        curtime->tm_mon + 1, 1900 + curtime->tm_year, \
        ##__VA_ARGS__);} while(0)

#define MULTI_DEBUG_PRINT_SYSLOG(fd, _fmt, ...) \
    do { \
    time_t rawtime; \
    struct tm *curtime; \
    time(&rawtime); \
    curtime = gmtime(&rawtime); \
    if (1) \
        MULTI_DEBUG_SYSLOG(LOG_INFO, _fmt, ##__VA_ARGS__); \
    MULTI_DEBUG_PRINT2(fd, MULTI_LOG_PREFIX _fmt, \
        curtime->tm_hour, \
        curtime->tm_min, curtime->tm_sec, curtime->tm_mday, \
        curtime->tm_mon + 1, 1900 + curtime->tm_year, \
        ##__VA_ARGS__);} while(0)
#endif
