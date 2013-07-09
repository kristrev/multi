#ifndef MULTI_MACROS_H
#define MULTI_MACROS_H

#include <sys/queue.h>

//var is the value to store the match in (NULL otherwise)
//head is the list
//field is list-pointer
//value is the value to look for
//func is the function to call for each list member, compares
//value and var. Returns 0 if equal, 1 if not
#define TAILQ_FIND_CUSTOM(var, head, field, value, func) do{   \
    TAILQ_FOREACH(var, head, field){                            \
        if(!func(var, value)){printf("Found match\n");                                   \
            break;}                                              \
    };                                                           \
} while(0)

#endif
