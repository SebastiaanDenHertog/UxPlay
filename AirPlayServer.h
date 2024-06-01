#ifndef AIRPLAYSERVER_H
#define AIRPLAYSERVER_H

#include <stddef.h>
#include <cstring>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <string>
#include <algorithm>
#include <vector>
#include <fstream>
#include <sstream>
#include <iterator>
#include <sys/stat.h>
#include <cstdio>
#include <stdarg.h>
#include <math.h>

#ifdef _WIN32 /*modifications for Windows compilation */
#include <glib.h>
#include <unordered_map>
#include <winsock2.h>
#include <iphlpapi.h>
#else
#include <glib-unix.h>
#include <sys/utsname.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <pwd.h>
#ifdef __linux__
#include <netpacket/packet.h>
#else
#include <net/if_dl.h>
#endif
#endif

#include "lib/raop.h"
#include "lib/stream.h"
#include "lib/logger.h"
#include "lib/dnssd.h"
#include "renderers/video_renderer.h"
#include "renderers/audio_renderer.h"

void log(int level, const char *format, ...);
extern "C" void log_callback(void *cls, int level, const char *msg);
size_t write_coverart(const char *filename, const void *image, size_t len);

class AirPlayServer
{
public:
    AirPlayServer(int port, const char *name);
    void initialize(int argc, char *argv[]);
    void run(int argc, char *argv[]);
    void stop();
    void reset();
    void restart();
    void reconnect();

private:
    bool file_has_write_access(const char *filename);
    char *create_pin_display(char *pin_str, int margin, int gap);
    void parse_arguments(int argc, char *argv[]);
    void dump_audio_to_file(unsigned char *data, int datalen, unsigned char type);
    void dump_video_to_file(unsigned char *data, int datalen);
    std::string find_uxplay_config_file();
    std::string find_mac();
    void append_hostname();
    bool validate_mac(char *mac_address);
    std::string random_mac();
    void process_metadata(int count, const std::string &dmap_tag, const unsigned char *metadata, int datalen);
    int parse_dmap_header(const unsigned char *metadata, char *tag, int *len);
    int parse_hw_addr(std::string str, std::vector<char> &hw_addr);
    const char *get_homedir();
    bool option_has_value(const int i, const int argc, std::string option, const char *next_arg);
    bool get_display_settings(std::string value, unsigned short *w, unsigned short *h, unsigned short *r);
    bool get_value(const char *str, unsigned int *n);
    bool get_ports(int nports, std::string option, const char *value, unsigned short *const port);
    bool get_videoflip(const char *str, videoflip_t *videoflip);
    bool get_videorotate(const char *str, videoflip_t *videoflip);
    void append_hostname(std::string &server_name);
    void process_metadata(int count, const char *dmap_tag, const unsigned char *metadata, int datalen);
    int register_dnssd();
    void unregister_dnssd();
    void stop_dnssd();
    int start_dnssd(std::vector<char> hw_addr, std::string name);
    bool check_client(char *deviceid);
    bool check_blocked_client(char *deviceid);
    int start_raop_server(unsigned short display[5], unsigned short tcp[3], unsigned short udp[3], bool debug_log);
    void stop_raop_server();
    void read_config_file(const char *filename, const char *uxplay_name);
    static void display_pin(void *cls, char *pin);
    static void export_dacp(void *cls, const char *active_remote, const char *dacp_id);
    static void conn_init(void *cls);
    static void conn_destroy(void *cls);
    static void conn_reset(void *cls, int timeouts, bool reset_video);
    static void conn_teardown(void *cls, bool *teardown_96, bool *teardown_110);
    static void audio_process(void *cls, raop_ntp_t *ntp, audio_decode_struct *data);
    static void video_process(void *cls, raop_ntp_t *ntp, h264_decode_struct *data);
    static void video_pause(void *cls);
    static void video_resume(void *cls);
    static void audio_flush(void *cls);
    static void video_flush(void *cls);
    static void audio_set_volume(void *cls, float volume);
    static void audio_get_format(void *cls, unsigned char *ct, unsigned short *spf, bool *usingScreen, bool *isMedia, uint64_t *audioFormat);
    static void video_report_size(void *cls, float *width_source, float *height_source, float *width, float *height);
    static void audio_set_coverart(void *cls, const void *buffer, int buflen);
    static void audio_set_progress(void *cls, unsigned int start, unsigned int curr, unsigned int end);
    static void audio_set_metadata(void *cls, const void *buffer, int buflen);
    static void register_client(void *cls, const char *device_id, const char *client_pk, const char *client_name);
    static bool check_register(void *cls, const char *client_pk);
    static void report_client_request(void *cls, char *deviceid, char *model, char *name, bool *admit);

    dnssd_t *dnssd;
    raop_t *raop;
    std::string server_name;
    bool audio_sync;
    bool video_sync;
    int64_t audio_delay_alac;
    int64_t audio_delay_aac;
    bool relaunch_video;
    bool reset_loop;
    unsigned int open_connections;
    std::string videosink;
    videoflip_t videoflip[2];
    bool use_video;
    unsigned char compression_type;
    std::string audiosink;
    int audiodelay;
    bool use_audio;
    bool new_window_closing_behavior;
    bool close_window;
    std::string video_parser;
    std::string video_decoder;
    std::string video_converter;
    bool show_client_FPS_data;
    unsigned int max_ntp_timeouts;
    FILE *video_dumpfile;
    std::string video_dumpfile_name;
    int video_dump_limit;
    int video_dumpfile_count;
    int video_dump_count;
    bool dump_video;
    FILE *audio_dumpfile;
    std::string audio_dumpfile_name;
    int audio_dump_limit;
    int audio_dumpfile_count;
    int audio_dump_count;
    bool dump_audio;
    unsigned char audio_type;
    unsigned char previous_audio_type;
    bool fullscreen;
    std::string coverart_filename;
    bool do_append_hostname;
    bool use_random_hw_addr;
    unsigned short display[5];
    bool debug_log;
    bool bt709_fix;
    int max_connections;
    unsigned short raop_port;
    unsigned short airplay_port;
    uint64_t remote_clock_offset;
    std::vector<std::string> allowed_clients;
    std::vector<std::string> blocked_clients;
    bool restrict_clients;
    bool setup_legacy_pairing;
    bool require_password;
    unsigned short pin;
    std::string keyfile;
    std::string mac_address;
    std::string dacpfile;
    bool registration_list;
    std::string pairing_register;
    std::vector<std::string> registered_keys;
    double db_low;
    double db_high;
    bool taper_volume;
    unsigned short tcp[3];
    unsigned short udp[3];
};

#endif // AIRPLAYSERVER_H