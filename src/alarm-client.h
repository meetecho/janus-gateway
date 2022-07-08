#ifndef ALARM_CLIENT_H
#define ALARM_CLIENT_H

#define ALARM_SEVERITY_ERROR "4"

#include <glib.h>
#include <jansson.h>
#include <stdio.h>
#include <curl/curl.h>

#include "log.h"
#include "mutex.h"
#include "utils.h"
#include "config.h"

/* 
* Alarm client initialization.
* Must be called before attempting to use the alarm client.
* @param config Janus config
* @returns 0 in case of success, a negative integer otherwise 
*/
int alarm_client_init(janus_config* config);

void send_alarm(const char* severity, const char* message);

void alarm_client_destroy(void);

#endif