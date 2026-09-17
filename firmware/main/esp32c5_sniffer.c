/*
 * Wi-Fi packet sniffer that streams a live PCAP capture to Wireshark (through SerialShark.py).
 *
 * ESP-IDF port, for the ESP32-C5, of the CprE 543 Arduino sketch.
 * Original author: Abir Mojumder
 *
 * Data path:  Wi-Fi driver task --sniff_out()--> ring buffer --serial_writer_task()--> USB-Serial-JTAG
 *
 * The native USB port (USB-Serial-JTAG) carries nothing but the PCAP byte stream. Logs go to UART0
 * (see sdkconfig.defaults), because any text inside the stream would corrupt the capture.
 *
 * Host commands (ASCII lines on the same USB port, all optional):
 *   START [<unix time in us>|0] [<nonce>]   restart the stream: "<<START>>[ <nonce>]\n" + PCAP global header.
 *                                           A non-zero time makes the packet timestamps wall-clock time.
 *   CHANNELS <spec>                         channels to scan: "6", "1,6,11", "1-11" or "1-13,36,149-165".
 *                                           A list of one channel is a lock. "0" or "AUTO" restores the
 *                                           list from menuconfig. CHANNEL is accepted as the same command.
 *   DWELL <ms>                              time spent on each channel before moving to the next one
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/ringbuf.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_rom_sys.h"
#include "nvs_flash.h"
#include "driver/usb_serial_jtag.h"

#if !CONFIG_SOC_USB_SERIAL_JTAG_SUPPORTED
#error "This firmware streams the capture over the USB-Serial-JTAG port, which this target does not have"
#endif

//bounds for the dwell time the host may ask for, in milliseconds
#define MIN_DWELL_MS 20
#define MAX_DWELL_MS 60000

//The line SerialShark.py waits for before it starts forwarding bytes to Wireshark
#define START_MARKER "<<START>>"
#define NONCE_MAX_LEN 16

#define FCS_LEN 4
//Longest MPDU 802.11 allows (a VHT/HE A-MSDU; sig_len is 14 bits wide on the ESP32-C5). Such a frame arrives
//in several chained RX buffers, which the driver joins into one payload before it calls the callback.
#define MAX_FRAME_LEN 11454

#define USB_RX_BUF_SIZE 256 //the driver requires more than 64
#define USB_WRITE_TIMEOUT pdMS_TO_TICKS(100)
#define USB_START_TIMEOUT pdMS_TO_TICKS(1000)

static const char *TAG = "sniffer";

//PCAP file format (https://wiki.wireshark.org/Development/LibpcapFileFormat). The ESP32-C5 is little
//endian, so writing these structs as they are gives the byte order the 0xa1b2c3d4 magic number announces.
typedef struct __attribute__((packed)) {
    uint32_t magic_num;     /* with 0xa1b2c3d4 every packet has a timestamp in seconds and microseconds */
    uint16_t version_major; /* major version number */
    uint16_t version_minor; /* minor version number */
    uint32_t thiszone;      /* GMT to local correction */
    uint32_t sigfigs;       /* accuracy of timestamps */
    uint32_t snaplen;       /* max length of captured packets, in octets */
    uint32_t network;       /* data link type */
} pcap_global_hdr_t;

typedef struct __attribute__((packed)) {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len; /* number of octets of packet saved in file */
    uint32_t orig_len; /* actual length of packet */
} pcap_rec_hdr_t;

#if CONFIG_SNIFFER_LINKTYPE_RADIOTAP
#define PCAP_NETWORK 127 /* LINKTYPE_IEEE802_11_RADIOTAP */

//Radiotap header with the fields Flags, Channel, dBm Antenna Signal and dBm Antenna Noise.
//Fields are aligned to their own size counted from the start of this header, hence the pad byte.
typedef struct __attribute__((packed)) {
    uint8_t it_version;
    uint8_t it_pad;
    uint16_t it_len;
    uint32_t it_present;
    uint8_t flags;
    uint8_t pad0;
    uint16_t chan_freq;  /* MHz */
    uint16_t chan_flags;
    int8_t dbm_antsignal;
    int8_t dbm_antnoise;
} radiotap_hdr_t;
_Static_assert(sizeof(radiotap_hdr_t) == 16, "radiotap header layout");

#define RADIOTAP_PRESENT ((1u << 1) | (1u << 3) | (1u << 5) | (1u << 6))
#define RADIOTAP_CHAN_CCK 0x0020
#define RADIOTAP_CHAN_OFDM 0x0040
#define RADIOTAP_CHAN_2GHZ 0x0080
#define RADIOTAP_CHAN_5GHZ 0x0100
#define LINK_HDR_LEN sizeof(radiotap_hdr_t)
#else
#define PCAP_NETWORK 105 /* LINKTYPE_IEEE802_11 */
#define LINK_HDR_LEN 0
#endif

#define MAX_RECORD_LEN (sizeof(pcap_rec_hdr_t) + LINK_HDR_LEN + MAX_FRAME_LEN)
//A record is sent with a single all-or-nothing write, and a ring buffer item may not be larger than half
//the buffer (minus its own 8 byte header), so the largest frame has to fit in both.
_Static_assert(MAX_RECORD_LEN <= CONFIG_SNIFFER_RINGBUF_SIZE / 2 - 8, "ring buffer too small for one record");
_Static_assert(MAX_RECORD_LEN <= CONFIG_SNIFFER_USB_TX_BUF_SIZE, "USB TX buffer too small for one record");

static const pcap_global_hdr_t s_pcap_global_hdr = {
    .magic_num = 0xa1b2c3d4,
    .version_major = 2,
    .version_minor = 4,
    .thiszone = 0,
    .sigfigs = 0,
    .snaplen = 65535,
    .network = PCAP_NETWORK,
};

typedef struct {
    bool has_time;
    int64_t epoch_us;
    char nonce[NONCE_MAX_LEN + 1];
} start_req_t;

static RingbufHandle_t s_ringbuf;
static QueueHandle_t s_start_queue;
static TaskHandle_t s_hop_task;

//Only the writer task touches the offset: sniff_out() stores the raw esp_timer value in the record
//and the writer turns it into a PCAP timestamp just before sending.
static int64_t s_time_offset_us;

static volatile uint32_t s_captured;
static volatile uint32_t s_dropped_ringbuf;
static volatile uint32_t s_dropped_usb;
static volatile uint32_t s_oversize;

//The channels the radio can tune to at all. A channel outside these sets is refused by the driver.
#define CHANNEL_IS_2G(c) ((c) >= 1 && (c) <= 14)
#define CHANNEL_IS_5G(c) (((c) >= 36 && (c) <= 64 && ((c) - 36) % 4 == 0) || \
                          ((c) >= 100 && (c) <= 144 && ((c) - 100) % 4 == 0) || \
                          ((c) >= 149 && (c) <= 177 && ((c) - 149) % 4 == 0))
#define CHANNEL_IS_VALID(c) (CHANNEL_IS_2G(c) || CHANNEL_IS_5G(c))

#if CONFIG_SNIFFER_BAND_5G
_Static_assert(CHANNEL_IS_5G(CONFIG_SNIFFER_START_CHANNEL), "start channel is not a 5 GHz channel");
#elif CONFIG_SNIFFER_BAND_2G
_Static_assert(CHANNEL_IS_2G(CONFIG_SNIFFER_START_CHANNEL), "start channel is not a 2.4 GHz channel");
#else
_Static_assert(CHANNEL_IS_VALID(CONFIG_SNIFFER_START_CHANNEL), "start channel is not a Wi-Fi channel");
#endif

static const uint8_t s_5g_channels[] = {
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144,
    149, 153, 157, 161, 165,
};

//The scan list: the channels visited in turn, s_dwell_ms on each. A list of one channel is a lock.
//Both are set at boot from menuconfig and can be replaced at any time by the host (CHANNELS, DWELL).
#define MAX_SCAN_CHANNELS (14 + sizeof(s_5g_channels))

static SemaphoreHandle_t s_scan_mutex; /* guards the three fields below */
static uint8_t s_scan_list[MAX_SCAN_CHANNELS];
static bool s_scan_refused[MAX_SCAN_CHANNELS]; /* channels the driver would not tune to */
static size_t s_scan_count;
static size_t s_scan_idx;

static volatile uint32_t s_dwell_ms = CONFIG_SNIFFER_HOP_INTERVAL_MS;
static volatile uint8_t s_channel; /* the channel the radio is on right now */

static void build_default_list(uint8_t *list, size_t *count);
static bool parse_channel_spec(const char *spec, uint8_t *list, size_t *count);
static void set_scan_list(const uint8_t *list, size_t count);

/* ---------------------------------------------------------------------------------------------
 * Capture: runs in the Wi-Fi driver task, so it must not block, log or touch the USB port
 * ------------------------------------------------------------------------------------------- */

#if CONFIG_SNIFFER_LINKTYPE_RADIOTAP
static void fill_radiotap(radiotap_hdr_t *rt, const wifi_pkt_rx_ctrl_t *rx_ctrl)
{
    uint8_t ch = rx_ctrl->channel ? rx_ctrl->channel : s_channel;
#if CONFIG_SOC_WIFI_HE_SUPPORT
    bool cck = rx_ctrl->cur_bb_format == RX_BB_FORMAT_11B;
#else
    bool cck = rx_ctrl->sig_mode == 0 && rx_ctrl->rate < 8;
#endif

    rt->it_version = 0;
    rt->it_pad = 0;
    rt->it_len = sizeof(*rt);
    rt->it_present = RADIOTAP_PRESENT;
    rt->flags = 0; /* the FCS is stripped, so "frame includes FCS" stays clear */
    rt->pad0 = 0;
    if (ch <= 14) {
        rt->chan_freq = (ch == 14) ? 2484 : 2407 + 5 * ch;
        rt->chan_flags = RADIOTAP_CHAN_2GHZ | (cck ? RADIOTAP_CHAN_CCK : RADIOTAP_CHAN_OFDM);
    } else {
        rt->chan_freq = 5000 + 5 * ch;
        rt->chan_flags = RADIOTAP_CHAN_5GHZ | RADIOTAP_CHAN_OFDM;
    }
    rt->dbm_antsignal = rx_ctrl->rssi;
    rt->dbm_antnoise = rx_ctrl->noise_floor;
}
#endif

//Callback method to capture promiscuous packets
static void sniff_out(void *buf, wifi_promiscuous_pkt_type_t type)
{
    //received packet
    const wifi_promiscuous_pkt_t *pak = (const wifi_promiscuous_pkt_t *)buf;

    //MISC packets have no payload, and a non-zero rx_state marks a frame received with errors
    if (type == WIFI_PKT_MISC || pak->rx_ctrl.rx_state != 0) {
        return;
    }

    //sig_len counts the 4 byte FCS. Neither link type announces an FCS, so it is cut off,
    //otherwise Wireshark shows the frames as malformed.
    uint32_t len = pak->rx_ctrl.sig_len;
    if (len <= FCS_LEN) {
        return;
    }
    len -= FCS_LEN;
    if (len > MAX_FRAME_LEN) {
        s_oversize++;
        return;
    }

    //time of receiving packet (64 bit, the 32 bit rx_ctrl.timestamp wraps after 71 minutes)
    int64_t now_us = esp_timer_get_time();

    //One ring buffer item is one complete PCAP record, so a record is either sent whole or dropped whole
    //and the stream never loses its framing. The payload is only valid until this callback returns.
    uint32_t incl_len = LINK_HDR_LEN + len;
    uint8_t *item = NULL;
    if (xRingbufferSendAcquire(s_ringbuf, (void **)&item, sizeof(pcap_rec_hdr_t) + incl_len, 0) != pdTRUE) {
        s_dropped_ringbuf++;
        return;
    }

    pcap_rec_hdr_t rec = {
        .incl_len = incl_len,
        .orig_len = incl_len,
    };
    memcpy(&rec.ts_sec, &now_us, sizeof(now_us)); /* raw for now, see finish_record() */
    memcpy(item, &rec, sizeof(rec));
#if CONFIG_SNIFFER_LINKTYPE_RADIOTAP
    radiotap_hdr_t rt;
    fill_radiotap(&rt, &pak->rx_ctrl);
    memcpy(item + sizeof(rec), &rt, sizeof(rt));
#endif
    memcpy(item + sizeof(rec) + LINK_HDR_LEN, pak->payload, len);
    xRingbufferSendComplete(s_ringbuf, item);
    s_captured++;
}

/* ---------------------------------------------------------------------------------------------
 * Serial output: the writer task is the only one that writes to the USB port
 * ------------------------------------------------------------------------------------------- */

//Replace the raw esp_timer value stored by sniff_out() with the PCAP timestamp (seconds, microseconds)
static void finish_record(uint8_t *item)
{
    int64_t raw_us;
    memcpy(&raw_us, item, sizeof(raw_us));
    uint64_t ts = (uint64_t)(raw_us + s_time_offset_us);
    uint32_t sec = ts / 1000000ULL;
    uint32_t usec = ts % 1000000ULL;
    memcpy(item, &sec, sizeof(sec));
    memcpy(item + sizeof(sec), &usec, sizeof(usec));
}

//Start marker line followed by the PCAP global header, sent in one piece
static bool send_start(const char *nonce)
{
    uint8_t out[1 + sizeof(START_MARKER) + NONCE_MAX_LEN + 1 + sizeof(s_pcap_global_hdr)];
    int n;
    if (nonce && nonce[0]) {
        n = snprintf((char *)out, sizeof(out), "\n" START_MARKER " %s\n", nonce);
    } else {
        n = snprintf((char *)out, sizeof(out), "\n" START_MARKER "\n");
    }
    memcpy(out + n, &s_pcap_global_hdr, sizeof(s_pcap_global_hdr));
    n += sizeof(s_pcap_global_hdr);
    return usb_serial_jtag_write_bytes(out, n, USB_START_TIMEOUT) == n;
}

static void restart_stream(const start_req_t *req)
{
    //Frames captured before the restart belong to the previous stream
    size_t size;
    void *item;
    while ((item = xRingbufferReceive(s_ringbuf, &size, 0)) != NULL) {
        vRingbufferReturnItem(s_ringbuf, item);
    }
    if (req->has_time) {
        s_time_offset_us = req->epoch_us - esp_timer_get_time();
    }
    if (!send_start(req->nonce)) {
        ESP_LOGW(TAG, "start marker not sent, is the host reading the port?");
    }
}

static void serial_writer_task(void *arg)
{
    //Sent once at boot like the Arduino sketch did, so resetting the board also (re)starts a capture
    start_req_t req = { 0 };
    restart_stream(&req);

    for (;;) {
        if (xQueueReceive(s_start_queue, &req, 0) == pdTRUE) {
            ESP_LOGI(TAG, "stream restarted by host%s", req.has_time ? ", clock synchronised" : "");
            restart_stream(&req);
        }

        size_t size;
        uint8_t *item = xRingbufferReceive(s_ringbuf, &size, pdMS_TO_TICKS(100));
        if (item == NULL) {
            continue;
        }
        finish_record(item);
        //All or nothing: when the host is not reading, the write times out and the record is dropped
        if (usb_serial_jtag_write_bytes(item, size, USB_WRITE_TIMEOUT) != (int)size) {
            s_dropped_usb++;
        }
        vRingbufferReturnItem(s_ringbuf, item);
    }
}

/* ---------------------------------------------------------------------------------------------
 * Host commands
 * ------------------------------------------------------------------------------------------- */

static bool nonce_is_valid(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > NONCE_MAX_LEN) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        bool alnum = (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z');
        if (!alnum) {
            return false;
        }
    }
    return true;
}

static void handle_command(char *line)
{
    char *save = NULL;
    char *cmd = strtok_r(line, " \t\r", &save);
    if (cmd == NULL) {
        return;
    }

    if (strcmp(cmd, "START") == 0) {
        start_req_t req = { 0 };
        char *time_arg = strtok_r(NULL, " \t\r", &save);
        char *nonce_arg = strtok_r(NULL, " \t\r", &save);
        if (time_arg) {
            char *end;
            unsigned long long epoch_us = strtoull(time_arg, &end, 10);
            if (*end == '\0' && epoch_us != 0 && epoch_us <= INT64_MAX) {
                req.has_time = true;
                req.epoch_us = (int64_t)epoch_us;
            }
        }
        if (nonce_arg && nonce_is_valid(nonce_arg)) {
            strlcpy(req.nonce, nonce_arg, sizeof(req.nonce));
        }
        xQueueOverwrite(s_start_queue, &req);
    } else if (strcmp(cmd, "CHANNEL") == 0 || strcmp(cmd, "CHANNELS") == 0) {
        //One channel ("6"), several ("1,6,11"), a range ("1-11") or a mix ("1-13,36,149-165").
        //"0", "AUTO" or no argument goes back to the list built from menuconfig.
        char *spec = strtok_r(NULL, " \t\r", &save);
        uint8_t list[MAX_SCAN_CHANNELS];
        size_t count = 0;
        if (spec == NULL || strcmp(spec, "0") == 0 || strcasecmp(spec, "AUTO") == 0) {
            build_default_list(list, &count);
        } else if (!parse_channel_spec(spec, list, &count)) {
            ESP_LOGW(TAG, "cannot use channel list '%s'", spec);
            return;
        }
        set_scan_list(list, count);
    } else if (strcmp(cmd, "DWELL") == 0) {
        char *ms_arg = strtok_r(NULL, " \t\r", &save);
        char *end;
        unsigned long ms = ms_arg ? strtoul(ms_arg, &end, 10) : 0;
        if (ms_arg == NULL || *end != '\0' || ms < MIN_DWELL_MS || ms > MAX_DWELL_MS) {
            ESP_LOGW(TAG, "DWELL needs a time in ms between %d and %d", MIN_DWELL_MS, MAX_DWELL_MS);
            return;
        }
        s_dwell_ms = (uint32_t)ms;
        xTaskNotifyGive(s_hop_task); /* use the new dwell time from now, not after the old one */
        ESP_LOGI(TAG, "dwell time %lu ms", ms);
    } else {
        ESP_LOGW(TAG, "unknown command '%s'", cmd);
    }
}

static void command_task(void *arg)
{
    char line[64];
    size_t len = 0;
    bool overflow = false;

    for (;;) {
        uint8_t rx[32];
        int n = usb_serial_jtag_read_bytes(rx, sizeof(rx), pdMS_TO_TICKS(200));
        for (int i = 0; i < n; i++) {
            if (rx[i] == '\n') {
                line[len] = '\0';
                if (!overflow) {
                    handle_command(line);
                }
                len = 0;
                overflow = false;
            } else if (len < sizeof(line) - 1) {
                line[len++] = (char)rx[i];
            } else {
                overflow = true; /* too long to be a command, ignore up to the next newline */
            }
        }
    }
}

/* ---------------------------------------------------------------------------------------------
 * Channel hopping
 * ------------------------------------------------------------------------------------------- */

//The list menuconfig asks for: one channel when hopping is off, otherwise every channel of the chosen bands
static void build_default_list(uint8_t *list, size_t *count)
{
    size_t n = 0;
#if CONFIG_SNIFFER_CHANNEL_HOPPING
#if !CONFIG_SNIFFER_BAND_5G
    for (uint8_t ch = 1; ch <= CONFIG_SNIFFER_2G_MAX_CHANNEL; ch++) {
        list[n++] = ch;
    }
#endif
#if CONFIG_SNIFFER_BAND_5G || CONFIG_SNIFFER_BAND_DUAL
    for (size_t i = 0; i < sizeof(s_5g_channels); i++) {
        list[n++] = s_5g_channels[i];
    }
#endif
#else
    list[n++] = CONFIG_SNIFFER_START_CHANNEL;
#endif
    *count = n;
}

static void list_add(uint8_t *list, size_t *count, unsigned ch)
{
    for (size_t i = 0; i < *count; i++) {
        if (list[i] == ch) {
            return; /* already asked for, do not spend dwell time on it twice */
        }
    }
    if (*count < MAX_SCAN_CHANNELS) {
        list[(*count)++] = (uint8_t)ch;
    }
}

//Parse "6", "1,6,11", "1-11" or "1-13,36,149-165". A single number has to be a real channel; a range
//quietly keeps the real channels inside it, so "36-64" gives 36,40,...,64 and "1-165" gives both bands.
static bool parse_channel_spec(const char *spec, uint8_t *list, size_t *count)
{
    *count = 0;
    while (*spec) {
        char *end;
        unsigned long lo = strtoul(spec, &end, 10);
        if (end == spec || lo == 0 || lo > 177) {
            return false;
        }
        unsigned long hi = lo;
        if (*end == '-') {
            spec = end + 1;
            hi = strtoul(spec, &end, 10);
            if (end == spec || hi < lo || hi > 177) {
                return false;
            }
            for (unsigned long ch = lo; ch <= hi; ch++) {
                if (CHANNEL_IS_VALID(ch)) {
                    list_add(list, count, ch);
                }
            }
        } else {
            if (!CHANNEL_IS_VALID(lo)) {
                return false;
            }
            list_add(list, count, lo);
        }
        if (*end == ',') {
            spec = end + 1;
            continue;
        }
        if (*end != '\0') {
            return false;
        }
        break;
    }
    return *count > 0;
}

static void set_scan_list(const uint8_t *list, size_t count)
{
    char text[MAX_SCAN_CHANNELS * 4 + 1];
    int len = 0;

    xSemaphoreTake(s_scan_mutex, portMAX_DELAY);
    memcpy(s_scan_list, list, count);
    memset(s_scan_refused, 0, sizeof(s_scan_refused)); /* a new list deserves a fresh try */
    s_scan_count = count;
    s_scan_idx = 0;
    for (size_t i = 0; i < count && len < (int)sizeof(text) - 5; i++) {
        len += snprintf(text + len, sizeof(text) - len, i ? ",%u" : "%u", list[i]);
    }
    xSemaphoreGive(s_scan_mutex);

    ESP_LOGI(TAG, "scanning %u channel(s): %s", (unsigned)count, text);
    if (s_hop_task) {
        xTaskNotifyGive(s_hop_task); /* apply now instead of at the end of the current dwell */
    }
}

static bool set_channel(uint8_t ch)
{
    //The secondary channel is not used: 20 MHz in 2.4 GHz, and the driver picks it itself in 5 GHz
    esp_err_t err = esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "channel %u not set: %s", ch, esp_err_to_name(err));
        return false;
    }
    s_channel = ch;
    return true;
}

static void channel_hop_task(void *arg)
{
    for (;;) {
        uint32_t wait_ms = s_dwell_ms;

        xSemaphoreTake(s_scan_mutex, portMAX_DELAY);
        if (s_scan_count == 0) {
            wait_ms = 1000; /* nothing to scan; the host can still send a new list */
        } else if (s_scan_count == 1) {
            //A single channel is a lock: tune once, then just wait for the host to change something.
            //Retried every second while the driver refuses it, in case the band mode is still settling.
            if (s_channel != s_scan_list[0]) {
                set_channel(s_scan_list[0]);
            }
            wait_ms = 1000;
        } else {
            //Move to the next channel the driver accepts
            for (size_t tries = 0; tries < s_scan_count; tries++) {
                size_t i = s_scan_idx;
                s_scan_idx = (s_scan_idx + 1) % s_scan_count;
                if (s_scan_refused[i]) {
                    continue;
                }
                if (set_channel(s_scan_list[i])) {
                    break;
                }
                //not allowed by the band mode or the regulatory domain, skip it from now on
                s_scan_refused[i] = true;
            }
        }
        xSemaphoreGive(s_scan_mutex);

        //wakes up early when the host sends a CHANNELS or DWELL command
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(wait_ms));
    }
}

/* ---------------------------------------------------------------------------------------------
 * Initialisation
 * ------------------------------------------------------------------------------------------- */

static void usb_serial_init(void)
{
    //ROM printf (early logs) can mirror its output to the USB port, keep it out of the capture stream
    esp_rom_install_channel_putc(2, NULL);

    usb_serial_jtag_driver_config_t usb_cfg = {
        .tx_buffer_size = CONFIG_SNIFFER_USB_TX_BUF_SIZE,
        .rx_buffer_size = USB_RX_BUF_SIZE,
    };
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&usb_cfg));
}

static void wifi_sniffer_init(void)
{
    //stack configuration initialization, pass cfg to esp_wifi_init function.
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    //NULL mode: receive only. (The Arduino sketch used AP mode, which also broadcasts beacons.)
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());

#if CONFIG_SOC_WIFI_SUPPORT_5G
    //Changing the band mode restarts the driver, so it is done before promiscuous mode is enabled
#if CONFIG_SNIFFER_BAND_DUAL
    const wifi_band_mode_t wanted_band_mode = WIFI_BAND_MODE_AUTO;
#elif CONFIG_SNIFFER_BAND_5G
    const wifi_band_mode_t wanted_band_mode = WIFI_BAND_MODE_5G_ONLY;
#else
    const wifi_band_mode_t wanted_band_mode = WIFI_BAND_MODE_2G_ONLY;
#endif
    wifi_band_mode_t band_mode;
    if (esp_wifi_get_band_mode(&band_mode) != ESP_OK || band_mode != wanted_band_mode) {
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_set_band_mode(wanted_band_mode));
    }
#endif

    //With the default AUTO policy the driver lets a sniffer tune to every channel. A MANUAL policy left
    //in NVS by other firmware would restrict the hop list to that country's channels.
    wifi_country_t country;
    if (esp_wifi_get_country(&country) == ESP_OK && country.policy != WIFI_COUNTRY_POLICY_AUTO) {
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_set_country_code("01", true));
    }

    //Management and data frames, aggregated ones included.
    //Not asked for: MISC frames, of which the driver only reports the length and no usable payload, and
    //FCS failed frames, whose bytes are corrupt by definition. Neither can become a valid PCAP record,
    //and sniff_out() drops them anyway should the driver deliver them.
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA |
                       WIFI_PROMIS_FILTER_MASK_DATA_MPDU | WIFI_PROMIS_FILTER_MASK_DATA_AMPDU,
    };
#if CONFIG_SNIFFER_CAPTURE_CTRL_FRAMES
    filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_CTRL;
    //Control frames are filtered a second time by subtype, and that filter lets nothing through by
    //default, so ACK, RTS, CTS, Block Ack, PS-Poll and CF-End all have to be asked for explicitly.
    const wifi_promiscuous_filter_t ctrl_filter = {
        .filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL,
    };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_ctrl_filter(&ctrl_filter));
#endif
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));

    //setting promiscuous mode here
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(sniff_out));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
}

void app_main(void)
{
    usb_serial_init();

    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    s_ringbuf = xRingbufferCreate(CONFIG_SNIFFER_RINGBUF_SIZE, RINGBUF_TYPE_NOSPLIT);
    s_start_queue = xQueueCreate(1, sizeof(start_req_t));
    s_scan_mutex = xSemaphoreCreateMutex();
    if (s_ringbuf == NULL || s_start_queue == NULL || s_scan_mutex == NULL) {
        ESP_LOGE(TAG, "out of memory");
        abort();
    }

    uint8_t list[MAX_SCAN_CHANNELS];
    size_t count;
    build_default_list(list, &count);
    set_scan_list(list, count); /* before the hop task exists, so it starts on the right channel */

    //The writer sends the start marker and the PCAP global header before the first frame can arrive
    xTaskCreate(serial_writer_task, "serial_writer", 4096, NULL, 6, NULL);
    wifi_sniffer_init();
    xTaskCreate(channel_hop_task, "channel_hop", 4096, NULL, 4, &s_hop_task);
    xTaskCreate(command_task, "command", 4096, NULL, 5, NULL);

    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(10000));
        ESP_LOGI(TAG, "ch %3u of %u (%" PRIu32 " ms) | captured %" PRIu32
                      " | dropped: buffer %" PRIu32 ", usb %" PRIu32 ", oversize %" PRIu32,
                 s_channel, (unsigned)s_scan_count, s_dwell_ms, s_captured, s_dropped_ringbuf,
                 s_dropped_usb, s_oversize);
    }
}
