/* File that handles information regarding casting data
 GenghisKhanDrip*/

#ifndef CASTING
#define CASTING

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

bool isHLSUrl(char* url);

typedef struct hls_cast_s {



} hls_cast_t;

void startHLSRequests(hls_cast_t* cast);


#endif
