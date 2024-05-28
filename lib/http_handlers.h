#include "casting.h"


static bool
check_protocol(const char *method, const char * url, const char * protocol) {
    if (!strcmp(url, "/pair-pin-start") ||
        !strcmp(url, "/pair-setup-pin") ||
        !strcmp(url, "/pair-setup") ||
        !strcmp(url, "/pair-verify") ||
        !strcmp(url, "/fp-setup") ||
        !strcmp(url, "/feedback") ||
        !strcmp(url, "/audioMode") ||
        !strcmp(method, "OPTIONS") ||
	!strcmp(method, "FLUSH") ||
	!strcmp(method, "TEARDOWN") ||
	!strcmp(method, "GET_PARAMETER") ||
        !strcmp(method, "SET_PARAMETER") || 
        !strcmp(method, "SETUP") ||
        !strcmp(method, "RECORD")) {
        return (!strncmp(protocol, "RTSP", 4));
    } else {
        return (!strncmp(protocol, "HTTP", 4));
    }
}

static void
http_handler_server_info(raop_conn_t *conn,
                            http_request_t *request, http_response_t *response,
                            char **response_data, int *response_datalen)  {

    assert(conn->raop->dnssd);

    int hw_addr_raw_len = 0;
    const char *hw_addr_raw = dnssd_get_hw_addr(conn->raop->dnssd, &hw_addr_raw_len);

    char *hw_addr = calloc(1, 3 * hw_addr_raw_len);
    //int hw_addr_len =
    utils_hwaddr_airplay(hw_addr, 3 * hw_addr_raw_len, hw_addr_raw, hw_addr_raw_len);

    plist_t r_node = plist_new_dict();

    plist_t features_node = plist_new_uint(0x27F); 
    plist_dict_set_item(r_node, "features", features_node);

    plist_t mac_address_node = plist_new_string(hw_addr);
    plist_dict_set_item(r_node, "macAddress", mac_address_node);

    plist_t model_node = plist_new_string(GLOBAL_MODEL);
    plist_dict_set_item(r_node, "model", model_node);

    plist_t os_build_node = plist_new_string("12B435");
    plist_dict_set_item(r_node, "osBuildVersion", os_build_node);

    plist_t protovers_node = plist_new_string("1.0");
    plist_dict_set_item(r_node, "protovers", protovers_node);

    plist_t source_version_node = plist_new_string(GLOBAL_VERSION);
    plist_dict_set_item(r_node, "srcvers", source_version_node);

    plist_t vv_node = plist_new_uint(strtol(AIRPLAY_VV, NULL, 10));
    plist_dict_set_item(r_node, "vv", vv_node);

    plist_t device_id_node = plist_new_string(hw_addr);
    plist_dict_set_item(r_node, "deviceid", device_id_node);


    plist_to_xml(r_node, response_data, (uint32_t *) response_datalen);

    /* last 2 characters in *response_data are '>' and 0x0a  (/n). (followed by '\0') */

    assert(*response_datalen == strlen(*response_data));

    /* this code removes the final '/n' in the xml plist textstring: is it necessary? */
    (*response_data)[*response_datalen] = '\0';
    (*response_datalen)--;
    
    plist_free(r_node);
    http_response_add_header(response, "Content-Type", "text/x-apple-plist+xml");
    free(hw_addr);
}

static void
http_handler_get_property(raop_conn_t *conn,
                            http_request_t *request, http_response_t *response,
                            char **response_data, int *response_datalen) {
    logger_log(conn->raop->logger, LOGGER_ERR, "client HTTP request POST getProperty is unhandled");
    assert(0);
}

static void
http_handler_reverse(raop_conn_t *conn,
                        http_request_t *request, http_response_t *response,
                        char **response_data, int *response_datalen) {

  //conn->cast_session = http_request_get_header(request, "X-Apple-Session-ID");
    const char *connection = http_request_get_header(request, "Connection");
    const char *upgrade = http_request_get_header(request, "Upgrade");
    logger_log(conn->raop->logger, LOGGER_INFO, "client requested reverse connection: %s  \"%s\"", connection, upgrade);
    http_response_add_header(response, "Connection", connection);
    http_response_add_header(response, "Upgrade", upgrade);
    *response_data = NULL;
    response_datalen = 0;
}

static void
http_handler_scrub(raop_conn_t *conn,
                      http_request_t *request, http_response_t *response,
                      char **response_data, int *response_datalen) {
    logger_log(conn->raop->logger, LOGGER_ERR, "client HTTP request POST scrub is unhandled");
    assert(0);
}

static void
http_handler_rate(raop_conn_t *conn,
                     http_request_t *request, http_response_t *response,
                     char **response_data, int *response_datalen) {
    logger_log(conn->raop->logger, LOGGER_ERR, "client HTTP request POST rate is unhandled");
    assert(0);
}

static void
http_handler_stop(raop_conn_t *conn,
                     http_request_t *request, http_response_t *response,
                     char **response_data, int *response_datalen) {
    logger_log(conn->raop->logger, LOGGER_ERR, "client HTTP request POST stop is unhandled");
    assert(0);
}

static void
http_handler_action(raop_conn_t *conn,
                       http_request_t *request, http_response_t *response,
                       char **response_data, int *response_datalen) {
    logger_log(conn->raop->logger, LOGGER_ERR, "client HTTP request POST action is unhandled");
    assert(0);
}

static void
http_handler_fpsetup2(raop_conn_t *conn,
                         http_request_t *request, http_response_t *response,
                         char **response_data, int *response_datalen) {
    logger_log(conn->raop->logger, LOGGER_WARNING, "client HTTP request POST fp-setup2 is unhandled");
    http_response_add_header(response, "Content-Type", "application/x-apple-binary-plist");
    *response_data = NULL;
    response_datalen = 0;
    int req_datalen;
    const unsigned char *req_data = (unsigned char *) http_request_get_data(request, &req_datalen);
    logger_log(conn->raop->logger, LOGGER_ERR, "only FairPlay version 0x03 is implemented, version is 0x%2.2x", req_data[4]);
}


static void
http_handler_playback_info(raop_conn_t *conn,
                      http_request_t *request, http_response_t *response,
                      char **response_data, int *response_datalen)
{
    logger_log(conn->raop->logger, LOGGER_ERR, "client HTTP request GET playback_info is unhandled");
    assert(0);
#if 0

    logger_log(conn->raop->logger, LOGGER_DEBUG, "http_handler_playback_info");

    plist_t r_node = plist_new_dict();

    plist_t duration = plist_new_real(300);
    plist_dict_set_item(r_node, "duration", duration);

    plist_t position = plist_new_real(0);
    plist_dict_set_item(r_node, "position", position);

    plist_t rate = plist_new_real(1);
    plist_dict_set_item(r_node, "rate", rate);

    plist_t readyToPlay = plist_new_uint(1);
    plist_dict_set_item(r_node, "readyToPlay", readyToPlay);

    plist_t playbackBufferEmpty = plist_new_uint(1);
    plist_dict_set_item(r_node, "playbackBufferEmpty", playbackBufferEmpty);

    plist_t playbackBufferFull = plist_new_uint(0);
    plist_dict_set_item(r_node, "playbackBufferFull", playbackBufferFull);

    plist_t playbackLikelyToKeepUp = plist_new_uint(1);
    plist_dict_set_item(r_node, "playbackLikelyToKeepUp", playbackLikelyToKeepUp);

    plist_t loadedTimeRanges = plist_new_array();
    plist_t loadedTimeRanges0 = plist_new_dict();
    plist_t durationLoad = plist_new_real(300);
    plist_dict_set_item(loadedTimeRanges0, "duration", durationLoad);
    plist_t start = plist_new_real(0.0);
    plist_dict_set_item(loadedTimeRanges0, "start", start);
    plist_array_append_item(loadedTimeRanges, loadedTimeRanges0);
    plist_dict_set_item(r_node, "loadedTimeRanges", loadedTimeRanges);

    plist_t seekableTimeRanges = plist_new_array();
    plist_t seekableTimeRanges0 = plist_new_dict();
    plist_t durationSeek = plist_new_real(300);
    plist_dict_set_item(seekableTimeRanges0, "duration", durationSeek);
    plist_t startSeek = plist_new_real(0.0);
    plist_dict_set_item(seekableTimeRanges0, "start", startSeek);
    plist_array_append_item(seekableTimeRanges, seekableTimeRanges0);
    plist_dict_set_item(r_node, "seekableTimeRanges", seekableTimeRanges);

    plist_to_xml(r_node, response_data, (uint32_t *) response_datalen);

   /* last 2 characters in *response_data are '>' and 0x0a  (/n). (followed by '\0') */

    assert(*response_datalen == strlen(*response_data));

    /* this code removes the final '/n' in the xml plist textstring: is it necessary? */
    (*response_data)[*response_datalen] = '\0';
    (*response_datalen)--;

    plist_free(r_node);

    http_response_add_header(response, "Content-Type", "text/x-apple-plist+xml");
#endif
}

static void
http_handler_set_property(raop_conn_t *conn,
                      http_request_t *request, http_response_t *response,
                      char **response_data, int *response_datalen)
{
    logger_log(conn->raop->logger, LOGGER_ERR, "client HTTP request PUT setProperty is unhandled");
    assert(0);
#if 0

    logger_log(conn->raop->logger, LOGGER_DEBUG, "http_handler_set_property");

    char* urlPiece = (char*) http_request_get_url(request);
    strremove(urlPiece, "/setProperty?");

    if (!strcmp(urlPiece, "reverseEndTime") || !strcmp(urlPiece, "forwardEndTime") || !strcmp(urlPiece, "actionAtItemEnd")) {
        plist_t errResponse = plist_new_dict();
        plist_t errCode = plist_new_uint(0);
        plist_dict_set_item(errResponse, "errorCode", errCode);
        plist_to_xml(errResponse, response_data, (uint32_t *) response_datalen);
        *response_datalen = *response_datalen - 1; //TODO: Check if this does anything
        printf("%s", *response_data);
        plist_free(errResponse);
        http_response_add_header(response, "Content-Type", "text/x-apple-plist+xml");
    } else {
        http_response_add_header(response, "Content-Length", "0");
    }
#endif
}

static void
http_handler_play(raop_conn_t *conn,
                      http_request_t *request, http_response_t *response,
                      char **response_data, int *response_datalen)
{
  //    logger_log(conn->raop->logger, LOGGER_ERR, "client HTTP request POST play is unhandled");
  //  assert(0);
  //#if 0
    size_t len;
    const char* Apple_session_ID = NULL;
    char* playback_uuid = NULL;
    char* playback_location = NULL;
    double start_pos_secs = 0.0;
    bool data_is_plist = false;
	
    logger_log(conn->raop->logger, LOGGER_DEBUG, "http_handler_play");
    assert(conn->casting_data);
    
    Apple_session_ID = http_request_get_header(request, "X-Apple-Session-ID");
    if (!Apple_session_ID) {
        logger_log(conn->raop->logger, LOGGER_ERR, "Play request had no X-Apple-Session-ID");
        goto play_error;
    }

    int request_datalen;    
    const char *request_data = http_request_get_data(request, &request_datalen);

    if (request_datalen > 0) {
        char *header_str = NULL;
        http_request_get_header_string(request, &header_str);
        logger_log(conn->raop->logger, LOGGER_INFO, "request header %s", header_str);
	data_is_plist = (strstr(header_str, "apple-binary-plist") != NULL);
    }
    if (data_is_plist) {
        plist_t req_root_node = NULL;
        plist_from_bin(request_data, request_datalen, &req_root_node);
        if (PLIST_IS_DICT(req_root_node)) {
            plist_t req_uuid_node = plist_dict_get_item(req_root_node, "uuid");
            if (!req_uuid_node) {
	      goto play_error;
            } else {
                plist_get_string_val(req_uuid_node, &playback_uuid);
            }
    
            plist_t req_content_location_node = plist_dict_get_item(req_root_node, "Content-Location");
            if (!req_content_location_node) {
	      goto play_error;
            } else {
                plist_get_string_val(req_content_location_node, &playback_location);
	    }

            plist_t req_start_position_seconds_node = plist_dict_get_item(req_root_node, "Start-Position-Seconds");
            if (!req_start_position_seconds_node) {
                logger_log(conn->raop->logger, LOGGER_INFO, "No Start-Position-Seconds in Play request");
            } else {
                plist_get_real_val(req_content_location_node, &start_pos_secs);
            }
        } else {
            logger_log(conn->raop->logger, LOGGER_ERR, "binary plist was not a DICT");
            goto play_error;
	}
    } else {
      logger_log(conn->raop->logger, LOGGER_ERR, "play data was not a binary plist");
      goto play_error;
    }


    conn->casting_data->start_pos_ms = (float) 1000 * start_pos_secs;

    len = strlen(Apple_session_ID);
    conn->casting_data->casting_session_id = (char *) malloc(len+1);
    strncpy(conn->casting_data->casting_session_id, Apple_session_ID, len + 1);
		
    len = strlen(playback_uuid);
    conn->casting_data->playback_uuid = (char *) malloc(len + 1);
    strncpy(conn->casting_data->playback_uuid, playback_uuid, len + 1);

    len = strlen(playback_location);
    conn->casting_data->playback_location = (char *) malloc(len + 1);
    strncpy(conn->casting_data->playback_location, playback_location, len + 1);

    logger_log(conn->raop->logger, LOGGER_INFO, "Casting Data:\nApple_sessionID %s\nuuid %s\nContent Location %s\nStart Position (msec) %f",
	       conn->casting_data->casting_session_id,
	       conn->casting_data->playback_uuid,
	       conn->casting_data->playback_location,
	       conn->casting_data->start_pos_ms);


    
    if (!isHLSUrl(conn->casting_data->playback_location)) {
        logger_log(conn->raop->logger, LOGGER_DEBUG, "Dont need HLS for this, for the future add a link to Gstreamer to download file and play");
    } else {
        logger_log(conn->raop->logger, LOGGER_DEBUG, "Needs HLS Ugh");
        conn->casting_data->requestid = 0;
        startHLSRequests(conn->raop->port, Apple_sessionID, playback_url, playback_location, start_pos_ms, );
    }
    
    response_data = NULL;
    response_datalen = 0;
    return;
 play_error:;
    logger_log(conn->raop->logger, LOGGER_ERR, "Couldn't find Plist Data for /play, Unhandled");
    http_response_destroy(response);
    response = http_response_init("RTSP/1.0", 400, "Bad Request");
    http_response_add_header(response, "Server", "AirTunes/"GLOBAL_VERSION);
    *response_data = NULL;
    response_datalen = 0;
    return;
}
    
static void
raop_handler_audiomode(raop_conn_t *conn,
                       http_request_t *request, http_response_t *response,
                       char **response_data, int *response_datalen) {
    logger_log(conn->raop->logger, LOGGER_ERR, "client HTTP request POST audioMode is unhandled");
}
