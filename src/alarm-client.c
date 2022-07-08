#include "alarm-client.h"

static char* endpoint;
static char* api_key;
static char* host;
static char* host_region;
static char* host_environment;

static volatile gint initialized = 0, stopping = 0;
static GThread *alarm_thread;
static void *alarm_client_thread(void *data);

/* Queue of alarms to handle */
static GAsyncQueue *alarms = NULL;
static json_t exit_alarm;
static void alarm_client_alarm_free(json_t *alarm) {
    if(!alarm || alarm == &exit_alarm)
        return;
    json_decref(alarm);
}

/* JSON serialization options */
static size_t json_format = JSON_COMPACT | JSON_PRESERVE_ORDER;

static size_t alarm_client_write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
    return size*nmemb;
}

static int config_get_item(janus_config* config, janus_config_item *alarm_config, const char* name, char** item, int confidential){
    janus_config_item *config_item = janus_config_get(config, alarm_config, janus_config_type_item, name);
    if(config_item && config_item->value){
        *item = strdup((char*)config_item->value);
        JANUS_LOG(LOG_INFO, "Alarm %s: %s\n", name, confidential ? "..." : *item);
        return 0;
    }
    else{
        JANUS_LOG(LOG_WARN, "Error reading %s from alarm config\n", name);
        return -1;
    }
}

int alarm_client_init(janus_config* config){

    JANUS_LOG(LOG_INFO, "Initializing alarm client\n");

    janus_config_item *alarm_config = janus_config_get_create(config, NULL, janus_config_type_category, "alarm");
    if(!alarm_config){
        JANUS_LOG(LOG_WARN, "Error getting alarm config\n");
        return -1;
    }

    if(config_get_item(config, alarm_config, "endpoint", &endpoint, FALSE) < 0
    || config_get_item(config, alarm_config, "api_key", &api_key, TRUE) < 0
    || config_get_item(config, alarm_config, "host", &host, FALSE) < 0
    || config_get_item(config, alarm_config, "host_region", &host_region, FALSE) < 0
    || config_get_item(config, alarm_config, "host_environment", &host_environment, FALSE) < 0){
        return -1;
    }

    /* Initialize libcurl, needed for sending alarms via HTTP POST */
    curl_global_init(CURL_GLOBAL_ALL);

    /* Initialize the alarms queue */
    alarms = g_async_queue_new_full((GDestroyNotify) alarm_client_alarm_free);

    g_atomic_int_set(&initialized, 1);

    /* Launch the thread that will handle incoming alarms */
    GError *error = NULL;
    alarm_thread = g_thread_try_new("alarm client thread", alarm_client_thread, NULL, &error);
    if(error != NULL) {
        g_atomic_int_set(&initialized, 0);
        JANUS_LOG(LOG_WARN, "Got error %d (%s) trying to launch the alarm client thread...\n",
            error->code, error->message ? error->message : "??");
        g_error_free(error);
        return -1;
    }
    JANUS_LOG(LOG_INFO, "Alarm client initialized!\n");
    return 0;
}

void send_alarm(const char* severity, const char* message){

    if(g_atomic_int_get(&stopping) || !g_atomic_int_get(&initialized)) {
        /* Janus is closing or the plugin is */
        return;
    }
    
    json_t *alarm = json_object();
    json_object_set_new(alarm, "action", json_string("EventsRouter"));
    json_object_set_new(alarm, "method", json_string("add_event"));

    json_t *data_array = json_array();

    char* device = malloc((strlen("ENT//KUBERNETES/Nina4/webrtc-janus-/") + strlen(host_region) + strlen(host_environment) + strlen(host) + 1 ) * sizeof(char));
    sprintf(device, "ENT/%s/KUBERNETES/Nina4/webrtc-janus-%s/%s", host_region, host_environment, host);

    json_t *data_obj = json_object();
    json_object_set_new(data_obj, "device", json_string(device));
    json_object_set_new(data_obj, "summary", json_string(message));
    json_object_set_new(data_obj, "message", json_string(message));
    json_object_set_new(data_obj, "component", json_string("300"));
    json_object_set_new(data_obj, "severity", json_string(severity));
    json_object_set_new(data_obj, "evclasskey", json_string("webrtc-janus"));
    json_object_set_new(data_obj, "evclass", json_string("/App/Nuance/NOD/webrtc-janus"));
    json_object_set_new(data_obj, "session", json_string("n/a"));

    json_array_append_new(data_array, data_obj);

    json_object_set_new(alarm, "data", data_array);
    json_object_set_new(alarm, "tid", json_string("1"));

    g_async_queue_push(alarms, alarm);
}

static void *alarm_client_thread(void *data){
    JANUS_LOG(LOG_VERB, "Joining alarm client thread\n");
    json_t *alarm = NULL;
    char* alarm_text = NULL;
    while(g_atomic_int_get(&initialized) && !g_atomic_int_get(&stopping)) {

        alarm = g_async_queue_pop(alarms);
        if(alarm == &exit_alarm){
            break;
        }
        /* Send alarm via via HTTP POST */
        CURLcode res;
        struct curl_slist *headers = NULL;
        CURL *curl = curl_easy_init();
        if(curl == NULL) {
            JANUS_LOG(LOG_WARN, "Error initializing CURL context\n");
        }
        else{
            curl_easy_setopt(curl, CURLOPT_URL, endpoint);
            headers = curl_slist_append(headers, "Content-Type: application/json");
            headers = curl_slist_append(headers, "Accept: application/json");
            char* api_key_header = malloc((strlen("z-api-key: ") + strlen(api_key) + 1) * sizeof(char));
            sprintf(api_key_header, "%s%s", "z-api-key: ", api_key);
            headers = curl_slist_append(headers, api_key_header);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            alarm_text =  json_dumps(alarm, json_format);
            JANUS_LOG(LOG_INFO, "Sending alarm...\n");
            if(alarm_text == NULL){
                JANUS_LOG(LOG_WARN, "Error parsing alarm to text\n");
            }
            else{
                //Get the message
                json_t* data = json_object_get(alarm, "data");
                json_t* first_data = json_array_get(data, 0);
                json_t* message = json_object_get(first_data, "message");
                const char* alarm_message = json_string_value(message);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDS, alarm_text);
                curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(alarm_text));
                curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &alarm_client_write_data);
                /* Don't wait forever (let's say, 10 seconds) */
                curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
                /* Send the request */
                res = curl_easy_perform(curl);
                if(res != CURLE_OK) {
                    JANUS_LOG(LOG_WARN, "Error sending http alarm [%s] to [%s]: %s\n", alarm_message, endpoint, curl_easy_strerror(res));
                } else {
                    JANUS_LOG(LOG_INFO, "Alarm [%s] successfully sent to [%s]!\n", alarm_message, endpoint);
                }
            }
            
        }
        /* Cleanup */
        if(curl){
            curl_easy_cleanup(curl);
        }	
        if(headers){
            curl_slist_free_all(headers);
        }
        if(alarm_text){
            free(alarm_text);
        }
        alarm_text = NULL;
        /* Done, let's unref the alarm */
        json_decref(alarm);
        alarm = NULL;
    }
    JANUS_LOG(LOG_VERB, "Leaving alarm client thread\n");
    return NULL;
}

void alarm_client_destroy(void){
    if(!g_atomic_int_get(&initialized)){
        return;
    }
    //Commented out so that the alarm client thread will send all remaining alarm before terminating
    //g_atomic_int_set(&stopping, 1);

    g_async_queue_push(alarms, &exit_alarm);
    if(alarm_thread != NULL) {
        g_thread_join(alarm_thread);
        alarm_thread = NULL;
    }

    g_async_queue_unref(alarms);
    alarms = NULL;

    g_free(endpoint);
    g_free(api_key);
    g_free(host);
    g_free(host_region);
    g_free(host_environment);

    g_atomic_int_set(&initialized, 0);
    g_atomic_int_set(&stopping, 0);
    JANUS_LOG(LOG_INFO, "Alarm client destroyed!\n");
}