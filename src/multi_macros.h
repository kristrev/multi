#ifndef MULTI_MACROS_H
#define MULTI_MACROS_H

#include <sys/queue.h>

//TODO: Implement a prorotype for func

//var is the value to store the match in (NULL otherwise)
//head is the list
//field is list-pointer
//value is the value to look for
//func is the function to call for each list member, compares
//value and var. Returns 0 if equal, 1 if not
#define TAILQ_FIND_CUSTOM(var, head, field, value, func) do{   \
    TAILQ_FOREACH(var, head, field){                            \
        if(!func(var, value))                                   \
            break;                                              \
    };                                                           \
} while(0)

#define LIST_FIND_CUSTOM(var, head, field, value, func) do{   \
    LIST_FOREACH(var, head, field){                            \
        if(!func(var, value))                                   \
            break;                                              \
    };                                                           \
} while(0)

//Head is the list head and field the element field. cb is the callback to call
//(accepts two void pointer arguments), var is the element in the list and data
//is user data to pass to callback
#define LIST_FOREACH_CB(head, field, cb, var, data) do{ \
    LIST_FOREACH(var, head, field){ \
        cb(var, data); \
    } \
} while(0)

#endif
