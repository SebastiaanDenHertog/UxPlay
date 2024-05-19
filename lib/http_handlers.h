static void
get_protocol(const char * url, char * protocol, int len) {
  if (!strcmp(url, "/server-info") ||
      !strcmp(url, "/playback-info") ||
      !strcmp(url, "/setProperty") ||
      !strcmp(url, "/getProperty") ||
      !strcmp(url, "/reverse") ||
      !strcmp(url, "/play") ||
      !strcmp(url, "/scrub") ||
      !strcmp(url, "/rate") ||
      !strcmp(url, "/stop") || 
      !strcmp(url, "/action") ||
      !strcmp(url, "/fp-setup2")) {
    snprintf(protocol, len, "HTTP/1.1");
  } else {
    snprintf(protocol, len, "RTSP/1.0");
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
    //plist_t mac_address_node = plist_new_string("AA:BB:CC:DD:EE:FF");
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
    //plist_t device_id_node = plist_new_string("AABBCCDDEEFF");
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
http_handler_playback_info(raop_conn_t *conn,
                            http_request_t *request, http_response_t *response,
                            char **response_data, int *response_datalen) {
    logger_log(conn->raop->logger, LOGGER_ERR, "client HTTP request GET playback_info is unhandled");
    assert(0);
}

static void
http_handler_set_property(raop_conn_t *conn,
                            http_request_t *request, http_response_t *response,
                            char **response_data, int *response_datalen) {
    logger_log(conn->raop->logger, LOGGER_ERR, "client HTTP request PUT setProperty is unhandled");
    assert(0);
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
    const char *upgrade;

    conn->cast_session = http_request_get_header(request, "X-Apple-Session-ID");
    upgrade = http_request_get_header(request, "Upgrade");
    logger_log(conn->raop->logger, LOGGER_INFO, "client requested reverse connection: %s  \"%s\"", conn->cast_session, upgrade);
    http_response_add_header(response, "Upgrade", upgrade);
    http_response_add_header(response, "Content-Length","0");
}


static void
http_handler_play(raop_conn_t *conn,
                     http_request_t *request, http_response_t *response,
                     char **response_data, int *response_datalen) {
    logger_log(conn->raop->logger, LOGGER_ERR, "client HTTP request POST play is unhandled");
    assert(0);
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
raop_handler_audiomode(raop_conn_t *conn,
                       http_request_t *request, http_response_t *response,
                       char **response_data, int *response_datalen) {
    logger_log(conn->raop->logger, LOGGER_ERR, "client HTTP request POST audioMode is unhandled");
}
