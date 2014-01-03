#include <linux/if_addr.h>

#include "multi_cmp.h"
#include "multi_link_shared.h"
#include "multi_shared.h"

//TODO: Look into merging some of the cmp methods
uint8_t multi_cmp_devname(void *a, void *b){
	struct multi_link_info_static *li = (struct multi_link_info_static *) a;
	char *dev_name = (char *) b;

	if(!strcmp((char*) li->dev_name, (char*) dev_name))
		return 0;
	else
		return 1;
}

uint8_t multi_cmp_ifidx(void *a, void *b){
    struct multi_link_info *li = (struct multi_link_info *) a;
    uint32_t *ifiIdx = (uint32_t*) b;

    if(li->ifi_idx == *ifiIdx)
        return 0;
    else
        return 1;
}

/* This function needs to be separate. It is used when flushing infromation */
uint8_t multi_cmp_ifidx_flush(void *a, void *b){
    struct multi_link_info *li = (struct multi_link_info *) a;
    struct ifaddrmsg *ifa = (struct ifaddrmsg *) b;

    //Ignore PPP interfaces, as they will not be flushed!
    if((li->state != GOT_IP_PPP && li->state != GOT_IP_AP) && li->ifi_idx == 
            ifa->ifa_index)
        return 0;
    else
        return 1;
}

