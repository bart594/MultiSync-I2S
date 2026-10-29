#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <poll.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <alsa/asoundlib.h>

#define AP_VERSION "3.5-PI-RESYNC-RV1106"

#define MAX_PACKET_SIZE       9216
#define RING_BUFFER_SIZE      (4 * 1024 * 1024)
#define RING_BUFFER_MASK      (RING_BUFFER_SIZE - 1)
#define SCREAM_HEADER_SIZE    5
#define SCREAM_FEEDBACK_MAGIC 0x53434642
#define DEFAULT_TCP_PKT_SIZE  1157
#define DEFAULT_PRELOAD_FRAMES 4096

/* Max 1 ms latency when network/ALSA have no work; yield the single CPU. */
#define ALSA_IDLE_SLEEP_US   1000

/* Virtual DAC is a test-only clock model, NEVER a physical I2S emulator. */
#define VDAC_DEFAULT_CAPACITY 8192
#define VDAC_DEFAULT_TICK_US 1000
#define VDAC_DEFAULT_KP 0.40  /* ppm per frame of smoothed FIFO error */
#define VDAC_DEFAULT_KI 0.006 /* ppm per frame-second of FIFO error */
#define VDAC_MAX_CORRECTION_PPM 100
#define VDAC_RX_IDLE_MS 150

/* Only affects test-only VDAC; hardware ALSA/MMAP feedback is unchanged. */
typedef enum {
    VDAC_PREFILL = 0, VDAC_LOCKED, VDAC_WARNING, VDAC_RESYNC,
    VDAC_FAULT, VDAC_IDLE
} vdac_status_t;

static const char *vdac_status_name(unsigned int status) {
    switch (status) {
    case VDAC_PREFILL: return "PREFILL";
    case VDAC_LOCKED: return "LOCKED";
    case VDAC_WARNING: return "WARNING";
    case VDAC_RESYNC: return "RESYNC";
    case VDAC_FAULT: return "FAULT";
    case VDAC_IDLE: return "IDLE";
    default: return "UNKNOWN";
    }
}

typedef enum {
    MODE_UDP,
    MODE_TCP,
    MODE_L2,
} receiver_mode_t;

typedef enum {
    STATE_PREFILLING,
    STATE_PLAYING,
} playback_state_t;

typedef struct {
    uint32_t sample_rate;
    uint8_t  sample_size;
    uint8_t  channels;
    uint8_t  channel_mask;
    bool     is_dsd;
    bool     end_of_track;
} scream_format_t;

struct scream_feedback_pkt {
    uint32_t magic;
    int32_t  ppm_drift;
} __attribute__((packed));

typedef struct {
    uint8_t buffer[RING_BUFFER_SIZE];
    __attribute__((aligned(64))) volatile size_t write_pos;
    __attribute__((aligned(64))) volatile size_t read_pos;
    volatile size_t drop_count;
    volatile size_t drop_bytes;
} spsc_ring_t;

/* Counters use 32-bit atomic operations: native/lock-free on ARMv7.
 * Values are exchanged by the non-RT main thread at DIAG_INTERVAL_MS.
 * Packet loss on the wire cannot be inferred without sender sequence IDs. */
typedef struct {
    unsigned int rx_packets;
    unsigned int rx_wire_bytes;
    unsigned int rx_audio_bytes;
    unsigned int invalid_headers;
    unsigned int short_packets;
    unsigned int queued_audio_bytes;
    unsigned int ring_drop_packets;
    unsigned int ring_drop_bytes;
    unsigned int discarded_on_reinit;
    unsigned int rebuffer_events;
    unsigned int alsa_frames_written;
    unsigned int alsa_errors;
    unsigned int alsa_xruns;
    unsigned int rw_discarded_frames;
    unsigned int format_reinits;
    unsigned int format_failures;
    unsigned int vdac_frames_consumed;
    unsigned int vdac_underflow_events;
    unsigned int vdac_missing_frames;
    unsigned int vdac_frames_accepted;
    unsigned int vdac_capacity_frames; /* atomic snapshot, not exchange */
    unsigned int vdac_fill_frames;     /* atomic snapshot, not exchange */
    unsigned int feedback_sent;
    unsigned int vdac_resync_events;
    unsigned int vdac_warning_events;
    unsigned int vdac_fault_events;
    unsigned int vdac_sync_state;
    int vdac_pi_p_milli;  /* milli-ppm, atomic snapshot */
    int vdac_pi_i_milli;
    int last_feedback_ppm;
    int last_alsa_delay_frames;
} diagnostics_t;

typedef struct {
    receiver_mode_t mode;
    char iface[16];
    char alsa_device[64];
    int port;
    uint16_t eth_type;
    size_t tcp_packet_size;
    int dsd_rate_mult;

    /* SO_BUSY_POLL window in microseconds. 0 = disabled.
     * On single-core RV1106 use 0 (default) or very small (20-50 us) --
     * busy-poll burns the only core while polling. Requires CAP_NET_ADMIN. */
    int udp_busy_poll_us;

    snd_pcm_uframes_t cfg_buffer_frames;
    snd_pcm_uframes_t cfg_period_frames;
    size_t preload_frames;
    bool feedback_pll;
    bool use_mmap_cfg;
    bool diag_enabled;
    unsigned int diag_interval_ms;
    bool vdac_enabled;
    int vdac_rate_ppm;
    size_t vdac_buffer_frames;
    unsigned int vdac_tick_us;
    bool vdac_pi_enabled;
    double vdac_kp;
    double vdac_ki;
    int vdac_max_correction_ppm;
    unsigned int vdac_warn_hold_ms;
    unsigned int vdac_resync_hold_ms;
    unsigned int vdac_resync_limit;
    unsigned int vdac_resync_window_s;
    char vdac_csv_path[256];
    FILE *vdac_csv_file; /* only main thread writes */
    double vdac_log_elapsed;
    volatile unsigned int vdac_last_rx_ms;
    volatile bool vdac_eot;
    /* Virtual device state is exclusively owned by the ALSA worker. */
    size_t vdac_fill;
    size_t vdac_capacity;
    double vdac_phase;
    uint32_t vdac_rate;
    struct timespec vdac_prev_tick;
    bool vdac_clock_running;
    vdac_status_t vdac_status;
    double vdac_ema;
    double vdac_integral;
    uint64_t vdac_last_pi_ns;
    uint64_t vdac_sat_start_ns;
    uint64_t vdac_extreme_start_ns;
    uint64_t vdac_warn_start_ns;
    uint64_t vdac_resync_window_start_ns;
    unsigned int vdac_resync_window_count;
    diagnostics_t diag;

    int sock_fd;
    int tcp_client_fd;
    pthread_mutex_t tcp_mutex;
    pthread_mutex_t fmt_mutex;
    snd_pcm_t *pcm_handle;
    bool use_mmap_active;
    volatile bool dsd_swap_endian;

    spsc_ring_t ring;
    scream_format_t current_fmt;
    scream_format_t pending_fmt;
    uint32_t fmt_version;
    volatile bool fmt_change_requested;
    volatile bool fmt_failed;
    bool fmt_initialized;

    pthread_t net_thread;
    pthread_t alsa_thread;
    volatile bool running;

    struct sockaddr_in host_udp_addr;
    struct sockaddr_ll host_l2_addr;
    volatile bool has_host_addr;
    bool host_mac_configured;
    uint8_t static_host_mac[ETH_ALEN];
} receiver_ctx_t;

static receiver_ctx_t g_ctx;

#define DIAG_ADD(ctx, field, amount) do { \
    if ((ctx)->diag_enabled) \
        __atomic_fetch_add(&(ctx)->diag.field, (unsigned int)(amount), __ATOMIC_RELAXED); \
} while (0)

static inline unsigned int diag_take(unsigned int *value) {
    return __atomic_exchange_n(value, 0U, __ATOMIC_RELAXED);
}

static uint64_t monotonic_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return 0;
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}

static unsigned int monotonic_ms32(void) {
    return (unsigned int)(monotonic_ns() / 1000000ULL);
}

static double timespec_sec(const struct timespec *t) {
    return (double)t->tv_sec + (double)t->tv_nsec / 1000000000.0;
}

/* Called only by the regular-priority main thread. Does not touch ALSA APIs. */

static void sig_handler(int sig) {
    (void)sig;
    g_ctx.running = false;
}

static void str_trim(char *s) {
    char *p = s;
    int l = strlen(p);
    while (l > 0 && isspace(p[l - 1])) p[--l] = 0;
    while (*p && isspace(*p)) ++p, --l;
    memmove(s, p, l + 1);
}

static bool load_config(const char *path, receiver_ctx_t *ctx) {
    FILE *fp = fopen(path, "r");
    if (!fp) return false;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        str_trim(line);
        if (line[0] == '#' || line[0] == ';' || line[0] == '\0') continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        str_trim(key);
        str_trim(val);

        if (*val == '\0') continue;

        if (strcasecmp(key, "MODE") == 0 || strcasecmp(key, "PROTOCOL") == 0) {
            if (strcasecmp(val, "l2") == 0 || strcasecmp(val, "raw") == 0) ctx->mode = MODE_L2;
            else if (strcasecmp(val, "tcp") == 0) ctx->mode = MODE_TCP;
            else ctx->mode = MODE_UDP;
        } else if (strcasecmp(key, "TCP") == 0) {
            if (atoi(val) == 1) ctx->mode = MODE_TCP;
            else if (ctx->mode != MODE_L2) ctx->mode = MODE_UDP;
        } else if (strcasecmp(key, "IFACE") == 0 || strcasecmp(key, "INTERFACE") == 0) {
            strncpy(ctx->iface, val, sizeof(ctx->iface) - 1);
            ctx->iface[sizeof(ctx->iface) - 1] = '\0';
        } else if (strcasecmp(key, "PORT") == 0) {
            ctx->port = atoi(val);
        } else if (strcasecmp(key, "ETHERTYPE") == 0 || strcasecmp(key, "ETH_TYPE") == 0) {
            ctx->eth_type = (uint16_t)strtoul(val, NULL, 16);
        } else if (strcasecmp(key, "HOST_MAC") == 0) {
            if (sscanf(val, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                       &ctx->static_host_mac[0], &ctx->static_host_mac[1], &ctx->static_host_mac[2],
                       &ctx->static_host_mac[3], &ctx->static_host_mac[4], &ctx->static_host_mac[5]) == 6) {
                ctx->host_mac_configured = true;
            }
        } else if (strcasecmp(key, "ALSA_DEV") == 0 || strcasecmp(key, "DEV") == 0) {
            strncpy(ctx->alsa_device, val, sizeof(ctx->alsa_device) - 1);
            ctx->alsa_device[sizeof(ctx->alsa_device) - 1] = '\0';
        } else if (strcasecmp(key, "ALSA_BUFFER_FRAMES") == 0) {
            ctx->cfg_buffer_frames = (snd_pcm_uframes_t)strtoul(val, NULL, 10);
        } else if (strcasecmp(key, "ALSA_PERIOD_FRAMES") == 0) {
            ctx->cfg_period_frames = (snd_pcm_uframes_t)strtoul(val, NULL, 10);
        } else if (strcasecmp(key, "PRELOAD_BUFFER_FRAMES") == 0 || strcasecmp(key, "PRELOAD_FRAMES") == 0) {
            ctx->preload_frames = (size_t)strtoul(val, NULL, 10);
        } else if (strcasecmp(key, "FEEDBACK_PLL") == 0) {
            ctx->feedback_pll = (atoi(val) != 0);
        } else if (strcasecmp(key, "MMAP") == 0) {
            ctx->use_mmap_cfg = (atoi(val) != 0);
        } else if (strcasecmp(key, "DIAG") == 0) {
            ctx->diag_enabled = (atoi(val) != 0);
        } else if (strcasecmp(key, "VDAC") == 0 || strcasecmp(key, "VIRTUAL_DAC") == 0) {
            ctx->vdac_enabled = (atoi(val) != 0);
        } else if (strcasecmp(key, "VDAC_RATE_PPM") == 0) {
            int ppm = atoi(val);
            if (ppm < -10000) ppm = -10000;
            if (ppm > 10000) ppm = 10000;
            ctx->vdac_rate_ppm = ppm;
        } else if (strcasecmp(key, "VDAC_PI") == 0) {
            ctx->vdac_pi_enabled = (atoi(val) != 0);
        } else if (strcasecmp(key, "VDAC_PI_KP") == 0) {
            double v = atof(val);
            if (v >= 0.0 && v <= 5.0) ctx->vdac_kp = v;
        } else if (strcasecmp(key, "VDAC_PI_KI") == 0) {
            double v = atof(val);
            if (v >= 0.0 && v <= 0.1) ctx->vdac_ki = v;
        } else if (strcasecmp(key, "VDAC_PLL_MAX_PPM") == 0) {
            int v = atoi(val);
            if (v >= 1 && v <= VDAC_MAX_CORRECTION_PPM)
                ctx->vdac_max_correction_ppm = v;
        } else if (strcasecmp(key, "VDAC_WARN_HOLD_MS") == 0) {
            int v = atoi(val);
            if (v >= 1000 && v <= 120000) ctx->vdac_warn_hold_ms = (unsigned int)v;
        } else if (strcasecmp(key, "VDAC_RESYNC_HOLD_MS") == 0) {
            int v = atoi(val);
            if (v >= 100 && v <= 5000) ctx->vdac_resync_hold_ms = (unsigned int)v;
        } else if (strcasecmp(key, "VDAC_RESYNC_LIMIT") == 0) {
            int v = atoi(val);
            if (v >= 1 && v <= 20) ctx->vdac_resync_limit = (unsigned int)v;
        } else if (strcasecmp(key, "VDAC_RESYNC_WINDOW_S") == 0) {
            int v = atoi(val);
            if (v >= 10 && v <= 3600) ctx->vdac_resync_window_s = (unsigned int)v;
        } else if (strcasecmp(key, "VDAC_CSV_PATH") == 0) {
            snprintf(ctx->vdac_csv_path, sizeof(ctx->vdac_csv_path), "%s", val);
        } else if (strcasecmp(key, "VDAC_BUFFER_FRAMES") == 0) {
            size_t frames = (size_t)strtoul(val, NULL, 10);
            if (frames < 128) frames = 128;
            if (frames > 262144) frames = 262144;
            ctx->vdac_buffer_frames = frames;
        } else if (strcasecmp(key, "VDAC_TICK_US") == 0) {
            int tick = atoi(val);
            if (tick < 250) tick = 250;
            if (tick > 20000) tick = 20000;
            ctx->vdac_tick_us = (unsigned int)tick;
        } else if (strcasecmp(key, "DIAG_INTERVAL_MS") == 0) {
            int interval = atoi(val);
            if (interval < 250) interval = 250;
            if (interval > 10000) interval = 10000;
            ctx->diag_interval_ms = (unsigned int)interval;
        } else if (strcasecmp(key, "TCP_PACKET_SIZE") == 0) {
            ctx->tcp_packet_size = (size_t)strtoul(val, NULL, 10);
            if (ctx->tcp_packet_size < 16) ctx->tcp_packet_size = DEFAULT_TCP_PKT_SIZE;
        } else if (strcasecmp(key, "DSD_RATE_MULT") == 0) {
            ctx->dsd_rate_mult = atoi(val);
            if (ctx->dsd_rate_mult != 1 && ctx->dsd_rate_mult != 32) ctx->dsd_rate_mult = 1;
        } else if (strcasecmp(key, "UDP_BUSY_POLL_US") == 0) {
            int v = atoi(val);
            if (v < 0) v = 0;
            if (v > 1000000) v = 1000000;
            ctx->udp_busy_poll_us = v;
        }
    }

    fclose(fp);
    printf("[CONFIG] Zaladowano: %s\n", path);
    return true;
}

static void try_load_default_configs(receiver_ctx_t *ctx, const char *user_path) {
    if (user_path && load_config(user_path, ctx)) return;
    if (load_config("config.txt", ctx)) return;
    if (load_config("/usr/scream/config.txt", ctx)) return;
    if (load_config("/etc/apscream.conf", ctx)) return;
    printf("[CONFIG] Brak pliku konfiguracyjnego - parametry domyslne.\n");
}

/* --- SPSC Ring Buffer --- */

static inline size_t ring_available(spsc_ring_t *r) {
    size_t wp = __atomic_load_n(&r->write_pos, __ATOMIC_ACQUIRE);
    size_t rp = __atomic_load_n(&r->read_pos, __ATOMIC_ACQUIRE);
    return (wp - rp) & RING_BUFFER_MASK;
}

static void diag_report(receiver_ctx_t *ctx, double seconds, double cpu_seconds,
                        size_t ring_min, size_t ring_max) {
    diagnostics_t *d = &ctx->diag;
    if (seconds <= 0.0) return;
    unsigned int pkts = diag_take(&d->rx_packets);
    unsigned int wire = diag_take(&d->rx_wire_bytes);
    unsigned int audio = diag_take(&d->rx_audio_bytes);
    unsigned int queued = diag_take(&d->queued_audio_bytes);
    unsigned int bad = diag_take(&d->invalid_headers);
    unsigned int small = diag_take(&d->short_packets);
    unsigned int drops = diag_take(&d->ring_drop_packets);
    unsigned int dropped_bytes = diag_take(&d->ring_drop_bytes);
    unsigned int flush = diag_take(&d->discarded_on_reinit);
    unsigned int rebuffer = diag_take(&d->rebuffer_events);
    unsigned int frames = diag_take(&d->alsa_frames_written);
    unsigned int errors = diag_take(&d->alsa_errors);
    unsigned int xruns = diag_take(&d->alsa_xruns);
    unsigned int lost_rw = diag_take(&d->rw_discarded_frames);
    unsigned int resets = diag_take(&d->format_reinits);
    unsigned int reset_fail = diag_take(&d->format_failures);
    unsigned int feedback = diag_take(&d->feedback_sent);
    int ppm = __atomic_load_n(&d->last_feedback_ppm, __ATOMIC_RELAXED);
    int alsa_delay = __atomic_load_n(&d->last_alsa_delay_frames, __ATOMIC_RELAXED);
    unsigned int vdac_consumed = diag_take(&d->vdac_frames_consumed);
    unsigned int vdac_received = diag_take(&d->vdac_frames_accepted);
    unsigned int vdac_underflows = diag_take(&d->vdac_underflow_events);
    unsigned int vdac_missing = diag_take(&d->vdac_missing_frames);
    unsigned int vdac_cap = __atomic_load_n(&d->vdac_capacity_frames, __ATOMIC_RELAXED);
    unsigned int vdac_fill = __atomic_load_n(&d->vdac_fill_frames, __ATOMIC_RELAXED);
    unsigned int vdac_rate = __atomic_load_n(&ctx->vdac_rate, __ATOMIC_RELAXED);
    unsigned int vdac_state = __atomic_load_n(&d->vdac_sync_state, __ATOMIC_RELAXED);
    int vdac_p_milli = __atomic_load_n(&d->vdac_pi_p_milli, __ATOMIC_RELAXED);
    int vdac_i_milli = __atomic_load_n(&d->vdac_pi_i_milli, __ATOMIC_RELAXED);
    unsigned int vdac_resyncs = diag_take(&d->vdac_resync_events);
    unsigned int vdac_warns = diag_take(&d->vdac_warning_events);
    unsigned int vdac_faults = diag_take(&d->vdac_fault_events);
    size_t ring_now = ring_available(&ctx->ring);
    /* CPU process time is guest-side approximation, not physical RV1106 load. */
    printf("[DIAG] RX %.0f pkt/s %.1f KiB/s (payload %.1f, queued %.1f) "
           "bad=%u short=%u\n",
           (double)pkts / seconds, (double)wire / seconds / 1024.0,
           (double)audio / seconds / 1024.0,
           (double)queued / seconds / 1024.0, bad, small);
    printf("[DIAG] Ring now=%zu KiB sampled_min=%zu max=%zu ",
           ring_now / 1024, ring_min / 1024, ring_max / 1024);
    printf("(%.1f%%) drops=%u (%u B) flush=%u B rebuffer=%u\n",
           (double)ring_now * 100.0 / (double)RING_BUFFER_SIZE,
           drops, dropped_bytes, flush, rebuffer);
    if (ctx->vdac_enabled) {
        printf("[DIAG] Backend=Virtual-DAC (ALSA bypassed) | fmt_ok=%u fmt_err=%u\n",
               resets, reset_fail);
    } else {
        printf("[DIAG] ALSA frames/s=%.0f err=%u xrun=%u rw_unwritten=%u "
               "delay=%d frames | fmt_ok=%u fmt_err=%u\n",
               (double)frames / seconds, errors, xruns, lost_rw,
               alsa_delay, resets, reset_fail);
    }
    if (ctx->vdac_enabled) {
        printf("[VDAC] clock=%u Hz %+d ppm | FIFO=%u/%u frames (%.1f ms) "
               "accepted/s=%.0f played/s=%.0f underflows=%u missing=%u frames\n",
               vdac_rate, ctx->vdac_rate_ppm, vdac_fill, vdac_cap,
               vdac_rate ? (double)vdac_fill * 1000.0 / vdac_rate : 0.0,
               (double)vdac_received / seconds, (double)vdac_consumed / seconds,
               vdac_underflows, vdac_missing);
        printf("[VDAC CTRL] state=%s P=%+.3f I=%+.3f ppm request=%+d ppm "
               "feedback=%s warn=%u resync=%u fault=%u\n",
               vdac_status_name(vdac_state), vdac_p_milli / 1000.0,
               vdac_i_milli / 1000.0, ppm,
               ctx->feedback_pll ? "on" : "off", vdac_warns, vdac_resyncs,
               vdac_faults);
        if (ctx->vdac_csv_file) {
            ctx->vdac_log_elapsed += seconds;
            fprintf(ctx->vdac_csv_file,
                    "%.3f,%u,%u,%u,%s,%d,%.3f,%.3f,%.0f,%.0f,%u,%u,%u,%u,%u\n",
                    ctx->vdac_log_elapsed, vdac_rate, vdac_fill, vdac_cap,
                    vdac_status_name(vdac_state), ppm, vdac_p_milli / 1000.0,
                    vdac_i_milli / 1000.0, (double)pkts / seconds,
                    (double)vdac_consumed / seconds, vdac_underflows,
                    vdac_missing, vdac_warns, vdac_resyncs, vdac_faults);
            fflush(ctx->vdac_csv_file);
        }
    }
    printf("[DIAG] PLL sent=%u last=%+d ppm | CPU(guest process)=%.1f%%\n",
           feedback, ppm, cpu_seconds / seconds * 100.0);
    fflush(stdout);
}

static inline size_t ring_free_space(spsc_ring_t *r) {
    return (RING_BUFFER_SIZE - 1) - ring_available(r);
}

static inline void ring_clear_consumer(spsc_ring_t *r) {
    size_t wp = __atomic_load_n(&r->write_pos, __ATOMIC_ACQUIRE);
    __atomic_store_n(&r->read_pos, wp, __ATOMIC_RELEASE);
}

static inline bool ring_push(spsc_ring_t *r, const uint8_t *data, size_t len) {
    size_t free_sp = ring_free_space(r);
    if (len > free_sp) {
        __atomic_fetch_add(&r->drop_count, 1, __ATOMIC_RELAXED);
        __atomic_fetch_add(&r->drop_bytes, len, __ATOMIC_RELAXED);
        return false;
    }
    size_t wp = __atomic_load_n(&r->write_pos, __ATOMIC_RELAXED);
    size_t first = RING_BUFFER_SIZE - wp;
    if (first >= len) {
        memcpy(r->buffer + wp, data, len);
    } else {
        memcpy(r->buffer + wp, data, first);
        memcpy(r->buffer, data + first, len - first);
    }
    __atomic_store_n(&r->write_pos, (wp + len) & RING_BUFFER_MASK, __ATOMIC_RELEASE);
    return true;
}

static inline size_t ring_peek(spsc_ring_t *r, uint8_t *dest, size_t len) {
    size_t avail = ring_available(r);
    if (avail < len) len = avail;
    if (len == 0) return 0;

    size_t rp = __atomic_load_n(&r->read_pos, __ATOMIC_RELAXED);
    size_t first = RING_BUFFER_SIZE - rp;
    if (first >= len) {
        memcpy(dest, r->buffer + rp, len);
    } else {
        memcpy(dest, r->buffer + rp, first);
        memcpy(dest + first, r->buffer, len - first);
    }
    return len;
}

static inline void ring_consume(spsc_ring_t *r, size_t len) {
    size_t rp = __atomic_load_n(&r->read_pos, __ATOMIC_RELAXED);
    __atomic_store_n(&r->read_pos, (rp + len) & RING_BUFFER_MASK, __ATOMIC_RELEASE);
}

static inline size_t ring_pop(spsc_ring_t *r, uint8_t *dest, size_t len) {
    size_t n = ring_peek(r, dest, len);
    if (n) ring_consume(r, n);
    return n;
}

/* --- DSD deinterleave: 8 ramek na iterację, dobra wektoryzacja NEON --- */

static inline void dsd_deinterleave_fast(uint8_t *src, size_t bytes, bool swap_endian) {
    size_t frames = bytes / 8;
    uint8_t tmp[8];
    while (frames >= 8) {
        for (int i = 0; i < 8; i++) {
            if (!swap_endian) {
                tmp[0] = src[0]; tmp[1] = src[2]; tmp[2] = src[4]; tmp[3] = src[6];
                tmp[4] = src[1]; tmp[5] = src[3]; tmp[6] = src[5]; tmp[7] = src[7];
            } else {
                tmp[0] = src[6]; tmp[1] = src[4]; tmp[2] = src[2]; tmp[3] = src[0];
                tmp[4] = src[7]; tmp[5] = src[5]; tmp[6] = src[3]; tmp[7] = src[1];
            }
            memcpy(src, tmp, 8);
            src += 8;
        }
        frames -= 8;
    }
    while (frames--) {
        if (!swap_endian) {
            tmp[0] = src[0]; tmp[1] = src[2]; tmp[2] = src[4]; tmp[3] = src[6];
            tmp[4] = src[1]; tmp[5] = src[3]; tmp[6] = src[5]; tmp[7] = src[7];
        } else {
            tmp[0] = src[6]; tmp[1] = src[4]; tmp[2] = src[2]; tmp[3] = src[0];
            tmp[4] = src[7]; tmp[5] = src[5]; tmp[6] = src[3]; tmp[7] = src[1];
        }
        memcpy(src, tmp, 8);
        src += 8;
    }
}

/* --- Nagłówek Scream --- */

static inline bool parse_scream_header(const uint8_t *buf, scream_format_t *fmt) {
    uint8_t b0 = buf[0];
    uint8_t b1 = buf[1];
    uint8_t b2 = buf[2];
    uint8_t b3 = buf[3];
    uint8_t b4 = buf[4];

    fmt->sample_size = b1;
    fmt->channels = b2;
    fmt->channel_mask = b3;
    fmt->is_dsd = (b1 == 1);
    fmt->end_of_track = (b4 & 0x80) != 0;

    if (!fmt->is_dsd && b1 != 16 && b1 != 24 && b1 != 32)
        return false;
    if (b2 < 2 || b2 > 8)
        return false;

    if (b0 >= 128) {
        fmt->sample_rate = 44100 * (b0 - 128);
    } else {
        fmt->sample_rate = 48000 * b0;
    }

    if (fmt->is_dsd) {
        fmt->sample_rate *= 2;
    }

    if (fmt->is_dsd) {
        if (fmt->channels != 2 || fmt->sample_rate > 705600) return false;
    } else {
        if (fmt->channels > 4 && fmt->sample_rate > 192000) return false;
        if (fmt->channels > 2 && fmt->sample_rate > 384000) return false;
        if (fmt->sample_rate > 768000) return false;
    }

    return (fmt->sample_rate > 0);
}

/* --- ALSA helpers ---
 * Wspólna struktura hw_params przekazywana przez wskaźnik - fix 1.1.
 */

static bool alsa_apply_format(receiver_ctx_t *ctx,
                              snd_pcm_hw_params_t *hw,
                              const scream_format_t *fmt,
                              unsigned int *out_rate)
{
    snd_pcm_hw_params_any(ctx->pcm_handle, hw);

    snd_pcm_format_t afmt;
    if (fmt->is_dsd) {
        if (snd_pcm_hw_params_test_format(ctx->pcm_handle, hw, SND_PCM_FORMAT_DSD_U32_BE) == 0) {
            afmt = SND_PCM_FORMAT_DSD_U32_BE;
        } else if (snd_pcm_hw_params_test_format(ctx->pcm_handle, hw, SND_PCM_FORMAT_DSD_U32_LE) == 0) {
            afmt = SND_PCM_FORMAT_DSD_U32_LE;
            ctx->dsd_swap_endian = true;
            printf("[ALSA] DAC wspiera DSD_U32_LE - aktywacja zamiany endiannessu.\n");
        } else {
            fprintf(stderr, "[ALSA] DAC nie wspiera DSD_U32 (BE ani LE)!\n");
            return false;
        }
    } else {
        switch (fmt->sample_size) {
            case 16: afmt = SND_PCM_FORMAT_S16_LE; break;
            case 24: afmt = SND_PCM_FORMAT_S24_3LE; break;
            default: afmt = SND_PCM_FORMAT_S32_LE; break;
        }
    }

    ctx->use_mmap_active = false;
    if (ctx->use_mmap_cfg) {
        if (snd_pcm_hw_params_set_access(ctx->pcm_handle, hw, SND_PCM_ACCESS_MMAP_INTERLEAVED) == 0) {
            ctx->use_mmap_active = true;
        } else {
            fprintf(stderr, "[ALSA] Brak wsparcia MMAP. Fallback do RW.\n");
            snd_pcm_hw_params_set_access(ctx->pcm_handle, hw, SND_PCM_ACCESS_RW_INTERLEAVED);
        }
    } else {
        snd_pcm_hw_params_set_access(ctx->pcm_handle, hw, SND_PCM_ACCESS_RW_INTERLEAVED);
    }

    if (snd_pcm_hw_params_set_format(ctx->pcm_handle, hw, afmt) < 0) {
        fprintf(stderr, "[ALSA] Urzadzenie nie wspiera formatu.\n");
        return false;
    }

    if (snd_pcm_hw_params_set_channels(ctx->pcm_handle, hw, fmt->channels) < 0) {
        fprintf(stderr, "[ALSA] Urzadzenie nie wspiera %u kanalow.\n", fmt->channels);
        return false;
    }

    unsigned int rate = fmt->sample_rate;
    if (fmt->is_dsd && ctx->dsd_rate_mult > 1) rate *= ctx->dsd_rate_mult;

    unsigned int expected = rate;
    if (snd_pcm_hw_params_set_rate_near(ctx->pcm_handle, hw, &rate, 0) < 0) return false;
    unsigned int diff = (rate > expected) ? (rate - expected) : (expected - rate);
    if (diff > ((expected / 1000) + 1)) {
        fprintf(stderr, "[ALSA] Odrzucono czestotliwosc: %u Hz (oczekiwano %u Hz).\n", rate, expected);
        return false;
    }

    *out_rate = rate;
    return true;
}

static bool alsa_apply_buffers(receiver_ctx_t *ctx,
                               snd_pcm_hw_params_t *hw,
                               unsigned int rate)
{
    snd_pcm_uframes_t period = ctx->cfg_period_frames;
    snd_pcm_uframes_t buffer = ctx->cfg_buffer_frames;

    if (!buffer || !period) {
        if (rate >= 352800) { period = 4096; buffer = 16384; }
        else if (rate >= 176400) { period = 2048; buffer = 8192; }
        else if (rate >= 88200) { period = 1024; buffer = 4096; }
        else { period = 512; buffer = 2048; }
    }

    snd_pcm_hw_params_set_period_size_near(ctx->pcm_handle, hw, &period, 0);
    snd_pcm_hw_params_set_buffer_size_near(ctx->pcm_handle, hw, &buffer);

    if (snd_pcm_hw_params(ctx->pcm_handle, hw) < 0) {
        fprintf(stderr, "[ALSA] Blad konfiguracji hw_params.\n");
        return false;
    }

    snd_pcm_sw_params_t *sw;
    snd_pcm_sw_params_alloca(&sw);
    snd_pcm_sw_params_current(ctx->pcm_handle, sw);
    snd_pcm_sw_params_set_start_threshold(ctx->pcm_handle, sw, buffer / 2);
    snd_pcm_sw_params_set_avail_min(ctx->pcm_handle, sw, period);
    snd_pcm_sw_params(ctx->pcm_handle, sw);

    snd_pcm_prepare(ctx->pcm_handle);

    printf("[ALSA Config] %s | %u Hz | Bufor: %lu r., Period: %lu r. (%.2f ms) | %s\n",
           ctx->alsa_device, rate,
           (unsigned long)buffer, (unsigned long)period,
           (double)buffer * 1000.0 / rate,
           ctx->use_mmap_active ? "Direct MMAP" : "Standard RW");
    return true;
}

static void alsa_warmup(receiver_ctx_t *ctx, const scream_format_t *fmt, unsigned int rate) {
    if (!ctx->pcm_handle) return;

    size_t bps = fmt->is_dsd ? 4 : (fmt->sample_size / 8);
    size_t bpf = fmt->channels * bps;
    uint8_t silence = fmt->is_dsd ? 0x69 : 0x00;

    snd_pcm_uframes_t frames = rate / 20; /* 50 ms */

    snd_pcm_uframes_t buf_frames = 0;
    snd_pcm_uframes_t period_frames = 0;
    if (snd_pcm_get_params(ctx->pcm_handle, &buf_frames, &period_frames) == 0 &&
        buf_frames > 0 && frames > buf_frames)
        frames = buf_frames;

    if (ctx->use_mmap_active) {
        snd_pcm_uframes_t rem = frames;
        while (rem && ctx->running) {
            const snd_pcm_channel_area_t *areas;
            snd_pcm_uframes_t off, chunk = rem;
            if (snd_pcm_mmap_begin(ctx->pcm_handle, &areas, &off, &chunk) < 0) break;
            if (!chunk) break;
            uint8_t *d = (uint8_t *)areas[0].addr + off * bpf;
            memset(d, silence, chunk * bpf);
            if (snd_pcm_mmap_commit(ctx->pcm_handle, off, chunk) != (snd_pcm_sframes_t)chunk) break;
            rem -= chunk;
        }
        if (snd_pcm_state(ctx->pcm_handle) == SND_PCM_STATE_PREPARED)
            snd_pcm_start(ctx->pcm_handle);
    } else {
        size_t bytes = frames * bpf;
        uint8_t *buf = malloc(bytes);
        if (buf) {
            memset(buf, silence, bytes);
            snd_pcm_uframes_t written = 0;
            while (written < frames && ctx->running) {
                snd_pcm_sframes_t n = snd_pcm_writei(ctx->pcm_handle,
                                                     buf + written * bpf,
                                                     frames - written);
                if (n < 0) {
                    if (n == -EINTR) continue;
                    snd_pcm_recover(ctx->pcm_handle, n, 0);
                    break;
                }
                written += n;
            }
            free(buf);
        }
    }
}

static bool reinit_alsa(receiver_ctx_t *ctx, const scream_format_t *fmt) {
    if (ctx->pcm_handle) {
        snd_pcm_drop(ctx->pcm_handle);
        snd_pcm_close(ctx->pcm_handle);
        ctx->pcm_handle = NULL;
    }
    ctx->dsd_swap_endian = false;

    int err = snd_pcm_open(&ctx->pcm_handle, ctx->alsa_device, SND_PCM_STREAM_PLAYBACK, 0);
    if (err < 0) {
        fprintf(stderr, "[ALSA] Blad otwarcia %s: %s\n", ctx->alsa_device, snd_strerror(err));
        return false;
    }

    snd_pcm_hw_params_t *hw;
    snd_pcm_hw_params_alloca(&hw);

    unsigned int rate = fmt->sample_rate;

    if (!alsa_apply_format(ctx, hw, fmt, &rate)) {
        snd_pcm_close(ctx->pcm_handle);
        ctx->pcm_handle = NULL;
        return false;
    }

    if (!alsa_apply_buffers(ctx, hw, rate)) {
        snd_pcm_close(ctx->pcm_handle);
        ctx->pcm_handle = NULL;
        return false;
    }

    alsa_warmup(ctx, fmt, rate);
    return true;
}

/* --- Virtual DAC clock (QEMU TEST ONLY) ---------------------------------
 * This is an intentionally simplified timed sink: no I2S, no DMA, no actual
 * ALSA samples, no DAC output and no bit-perfect validation. Frames taken
 * from the ring are counted in a simulated hardware FIFO, drained using
 * CLOCK_MONOTONIC at nominal_rate*(1+ppm/1e6). All state is owned by the
 * ALSA/VDAC thread. No additional RT threads or ALSA calls in VDAC mode.
 */
static bool vdac_init(receiver_ctx_t *ctx, const scream_format_t *fmt) {
    if (ctx->pcm_handle) {
        snd_pcm_drop(ctx->pcm_handle);
        snd_pcm_close(ctx->pcm_handle);
        ctx->pcm_handle = NULL;
    }
    uint64_t rate = fmt->sample_rate;
    if (fmt->is_dsd) rate *= (unsigned int)ctx->dsd_rate_mult;
    if (!rate || rate > UINT32_MAX) return false;
    __atomic_store_n(&ctx->vdac_rate, (uint32_t)rate, __ATOMIC_RELAXED);
    ctx->vdac_capacity = ctx->vdac_buffer_frames;
    ctx->vdac_fill = 0;
    ctx->vdac_phase = 0.0;
    ctx->vdac_clock_running = false;
    ctx->vdac_ema = -1.0;
    ctx->vdac_integral = 0.0;
    ctx->vdac_last_pi_ns = 0;
    ctx->vdac_sat_start_ns = 0;
    ctx->vdac_extreme_start_ns = 0;
    ctx->vdac_warn_start_ns = 0;
    ctx->vdac_resync_window_start_ns = 0;
    ctx->vdac_resync_window_count = 0;
    ctx->vdac_status = VDAC_PREFILL;
    __atomic_store_n(&ctx->diag.vdac_sync_state, VDAC_PREFILL, __ATOMIC_RELAXED);
    __atomic_store_n(&ctx->diag.vdac_pi_p_milli, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&ctx->diag.vdac_pi_i_milli, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&ctx->diag.last_feedback_ppm, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&ctx->vdac_eot, false, __ATOMIC_RELEASE);
    __atomic_store_n(&ctx->diag.vdac_fill_frames, 0U, __ATOMIC_RELAXED);
    __atomic_store_n(&ctx->diag.vdac_capacity_frames, (unsigned int)ctx->vdac_capacity, __ATOMIC_RELAXED);
    printf("[VDAC Config] %u Hz %+d ppm | FIFO=%zu frames (%.2f ms) | timed sink, no ALSA\n",
           ctx->vdac_rate, ctx->vdac_rate_ppm, ctx->vdac_capacity,
           (double)ctx->vdac_capacity * 1000.0 / ctx->vdac_rate);
    return true;
}

static void vdac_fill_from_ring(receiver_ctx_t *ctx, size_t bpf) {
    if (ctx->vdac_fill >= ctx->vdac_capacity) return;
    size_t available_frames = ring_available(&ctx->ring) / bpf;
    size_t space_frames = ctx->vdac_capacity - ctx->vdac_fill;
    size_t transfer = available_frames < space_frames ? available_frames : space_frames;
    if (transfer) {
        ring_consume(&ctx->ring, transfer * bpf);
        ctx->vdac_fill += transfer;
        DIAG_ADD(ctx, vdac_frames_accepted, transfer);
        __atomic_store_n(&ctx->diag.vdac_fill_frames, (unsigned int)ctx->vdac_fill, __ATOMIC_RELAXED);
    }
}

static void vdac_set_status(receiver_ctx_t *ctx, vdac_status_t status) {
    if (ctx->vdac_status == status) return;
    ctx->vdac_status = status;
    __atomic_store_n(&ctx->diag.vdac_sync_state, (unsigned int)status, __ATOMIC_RELAXED);
}

static void vdac_reset_controller(receiver_ctx_t *ctx) {
    ctx->vdac_ema = -1.0;
    ctx->vdac_integral = 0.0;
    ctx->vdac_last_pi_ns = 0;
    ctx->vdac_sat_start_ns = 0;
    ctx->vdac_warn_start_ns = 0;
    ctx->vdac_extreme_start_ns = 0;
    __atomic_store_n(&ctx->diag.vdac_pi_p_milli, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&ctx->diag.vdac_pi_i_milli, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&ctx->diag.last_feedback_ppm, 0, __ATOMIC_RELAXED);
}

static void vdac_start(receiver_ctx_t *ctx) {
    clock_gettime(CLOCK_MONOTONIC, &ctx->vdac_prev_tick);
    ctx->vdac_clock_running = true;
    ctx->vdac_phase = 0.0;
    vdac_reset_controller(ctx);
    vdac_set_status(ctx, VDAC_LOCKED);
}

static bool vdac_stream_recent(receiver_ctx_t *ctx);

/* Returns true if FIFO ran dry at a time when it should have been playing. */
static bool vdac_drain_elapsed(receiver_ctx_t *ctx) {
    if (!ctx->vdac_clock_running) return false;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return false;
    double dt = timespec_sec(&now) - timespec_sec(&ctx->vdac_prev_tick);
    ctx->vdac_prev_tick = now;
    if (dt <= 0.0) return false;
    double due = ctx->vdac_phase + dt * (double)ctx->vdac_rate *
                 (1.0 + (double)ctx->vdac_rate_ppm / 1000000.0);
    /* Account for long stalls without huge arithmetic or an endless catch-up. */
    if (due > 1000000000.0) due = 1000000000.0;
    size_t frames_due = (size_t)due;
    ctx->vdac_phase = due - (double)frames_due;
    if (!frames_due) return false;
    size_t consumed = frames_due < ctx->vdac_fill ? frames_due : ctx->vdac_fill;
    ctx->vdac_fill -= consumed;
    DIAG_ADD(ctx, vdac_frames_consumed, consumed);
    __atomic_store_n(&ctx->diag.vdac_fill_frames, (unsigned int)ctx->vdac_fill, __ATOMIC_RELAXED);
    if (consumed < frames_due) {
        size_t missing = frames_due - consumed;
        /* Do not count natural EOT/idle FIFO exhaustion as a clock fault. */
        if (vdac_stream_recent(ctx)) {
            DIAG_ADD(ctx, vdac_underflow_events, 1);
            DIAG_ADD(ctx, vdac_missing_frames, missing);
        }
        ctx->vdac_clock_running = false;
        ctx->vdac_phase = 0.0;
        return true;
    }
    return false;
}

/* SCFB is a custom APScream test protocol, NOT the Diretta protocol.
 * Positive correction means send FASTER; exactly how vdac_sender.py applies it. */
static void vdac_send_feedback(receiver_ctx_t *ctx, int correction) {
    if (!ctx->feedback_pll || !ctx->has_host_addr) return;
    struct scream_feedback_pkt fb = { htonl(SCREAM_FEEDBACK_MAGIC), htonl(correction) };
    ssize_t sent = -1;
    if (ctx->mode == MODE_UDP) {
        sent = sendto(ctx->sock_fd, &fb, sizeof(fb), MSG_DONTWAIT,
                      (struct sockaddr *)&ctx->host_udp_addr, sizeof(ctx->host_udp_addr));
    } else if (ctx->mode == MODE_L2) {
        sent = sendto(ctx->sock_fd, &fb, sizeof(fb), MSG_DONTWAIT,
                      (struct sockaddr *)&ctx->host_l2_addr, sizeof(ctx->host_l2_addr));
    } else if (ctx->mode == MODE_TCP) {
        pthread_mutex_lock(&ctx->tcp_mutex);
        if (ctx->tcp_client_fd >= 0)
            sent = send(ctx->tcp_client_fd, &fb, sizeof(fb), MSG_DONTWAIT | MSG_NOSIGNAL);
        pthread_mutex_unlock(&ctx->tcp_mutex);
    }
    if (sent == (ssize_t)sizeof(fb)) DIAG_ADD(ctx, feedback_sent, 1);
}

/* After a stopped sender, a DAC FIFO will eventually run empty. This is NOT
 * evidence of clock divergence. Explicit Scream end-of-track is preferred. */
static bool vdac_stream_recent(receiver_ctx_t *ctx) {
    if (__atomic_load_n(&ctx->vdac_eot, __ATOMIC_ACQUIRE)) return false;
    unsigned int last_ms = __atomic_load_n(&ctx->vdac_last_rx_ms, __ATOMIC_RELAXED);
    return last_ms != 0 &&
           (unsigned int)(monotonic_ms32() - last_ms) < VDAC_RX_IDLE_MS;
}

/* TEST-ONLY stop/re-prefill: drop FIFO and ring, NOT network socket or ALSA.
 * A repeated resync means that clocks or transport cannot be synchronized. */
static void vdac_stop_and_prefill(receiver_ctx_t *ctx, playback_state_t *play,
                                  bool abnormal, const char *reason) {
    ctx->vdac_clock_running = false;
    ctx->vdac_fill = 0;
    ctx->vdac_phase = 0.0;
    __atomic_store_n(&ctx->diag.vdac_fill_frames, 0U, __ATOMIC_RELAXED);
    ring_clear_consumer(&ctx->ring);
    *play = STATE_PREFILLING;
    vdac_reset_controller(ctx);
    vdac_send_feedback(ctx, 0); /* Release old correction held by sender. */
    if (!abnormal) {
        vdac_set_status(ctx, VDAC_IDLE);
        printf("[VDAC] IDLE: %s; waiting for new stream, no fault counted\n", reason);
        return;
    }
    uint64_t now = monotonic_ns();
    if (!ctx->vdac_resync_window_start_ns ||
        now - ctx->vdac_resync_window_start_ns >
            (uint64_t)ctx->vdac_resync_window_s * 1000000000ULL) {
        ctx->vdac_resync_window_start_ns = now;
        ctx->vdac_resync_window_count = 0;
    }
    ++ctx->vdac_resync_window_count;
    DIAG_ADD(ctx, vdac_resync_events, 1);
    vdac_set_status(ctx, VDAC_RESYNC);
    printf("[VDAC] RESYNC: %s (%u/%u in %u s), flush and prefill\n",
           reason, ctx->vdac_resync_window_count, ctx->vdac_resync_limit,
           ctx->vdac_resync_window_s);
    if (ctx->vdac_resync_window_count >= ctx->vdac_resync_limit) {
        vdac_set_status(ctx, VDAC_FAULT);
        DIAG_ADD(ctx, vdac_fault_events, 1);
        printf("[VDAC] FAULT: repeated resync; playback disabled until process restart\n");
    }
}

/* Controller runs every 100 ms; all controller and FIFO state is owned by
 * one worker. Conditional integration prevents PI wind-up on saturation. */
static int vdac_pi_step(receiver_ctx_t *ctx, uint64_t now_ns) {
    const double measured = (double)ctx->vdac_fill;
    ctx->vdac_ema = (ctx->vdac_ema < 0.0) ? measured
                   : (0.85 * ctx->vdac_ema + 0.15 * measured);
    const double target = (double)ctx->vdac_capacity * 0.5;
    const double error = target - ctx->vdac_ema;
    const double limit = (double)ctx->vdac_max_correction_ppm;
    const double p = ctx->vdac_kp * error;
    double dt = ctx->vdac_last_pi_ns ?
        (double)(now_ns - ctx->vdac_last_pi_ns) / 1000000000.0 : 0.0;
    if (dt < 0.0) dt = 0.0;
    if (dt > 0.25) dt = 0.25; /* no integral burst after a QEMU pause */
    ctx->vdac_last_pi_ns = now_ns;
    if (ctx->vdac_pi_enabled) {
        double candidate = ctx->vdac_integral + ctx->vdac_ki * error * dt;
        if (candidate > limit) candidate = limit;
        if (candidate < -limit) candidate = -limit;
        /* Do not integrate further into a saturated output; allow unwinding. */
        if (!((p + candidate > limit && error > 0.0) ||
              (p + candidate < -limit && error < 0.0)))
            ctx->vdac_integral = candidate;
    } else {
        ctx->vdac_integral = 0.0;
    }
    double output = p + ctx->vdac_integral;
    if (output > limit) output = limit;
    if (output < -limit) output = -limit;
    const int correction = (int)(output >= 0.0 ? output + 0.5 : output - 0.5);
    __atomic_store_n(&ctx->diag.vdac_pi_p_milli,
                     (int)(p * 1000.0), __ATOMIC_RELAXED);
    __atomic_store_n(&ctx->diag.vdac_pi_i_milli,
                     (int)(ctx->vdac_integral * 1000.0), __ATOMIC_RELAXED);
    __atomic_store_n(&ctx->diag.last_feedback_ppm, correction, __ATOMIC_RELAXED);
    return correction;
}

/* Warn only after sustained limit or sustained FIFO deviation. Resync only
 * when FIFO is critically near empty/full for a hold interval; an abrupt
 * packet burst or a brief scheduling hiccup cannot trigger it immediately. */
static bool vdac_check_sync(receiver_ctx_t *ctx, playback_state_t *play,
                            int correction, uint64_t now_ns) {
    if (ctx->vdac_status == VDAC_FAULT) return true;
    if (!vdac_stream_recent(ctx)) {
        ctx->vdac_sat_start_ns = 0;
        ctx->vdac_warn_start_ns = 0;
        ctx->vdac_extreme_start_ns = 0;
        return false;
    }
    double fraction = (double)ctx->vdac_fill / (double)ctx->vdac_capacity;
    const bool extreme = fraction < 0.10 || fraction > 0.90;
    const bool outside = fraction < 0.20 || fraction > 0.80;
    const bool saturated = correction >= ctx->vdac_max_correction_ppm ||
                           correction <= -ctx->vdac_max_correction_ppm;
    if (extreme) {
        if (!ctx->vdac_extreme_start_ns) ctx->vdac_extreme_start_ns = now_ns;
        else if (now_ns - ctx->vdac_extreme_start_ns >=
                 (uint64_t)ctx->vdac_resync_hold_ms * 1000000ULL) {
            vdac_stop_and_prefill(ctx, play, true, "critical FIFO <10% or >90%");
            return true;
        }
    } else ctx->vdac_extreme_start_ns = 0;
    if (outside || saturated) {
        if (!ctx->vdac_warn_start_ns) ctx->vdac_warn_start_ns = now_ns;
        if (now_ns - ctx->vdac_warn_start_ns >=
            (uint64_t)ctx->vdac_warn_hold_ms * 1000000ULL &&
            ctx->vdac_status != VDAC_WARNING) {
            vdac_set_status(ctx, VDAC_WARNING);
            DIAG_ADD(ctx, vdac_warning_events, 1);
            printf("[VDAC] WARNING: persistent FIFO deviation or PI at limit; "
                   "fill=%zu/%zu feedback=%+d ppm\n",
                   ctx->vdac_fill, ctx->vdac_capacity, correction);
        }
    } else {
        ctx->vdac_warn_start_ns = 0;
        vdac_set_status(ctx, VDAC_LOCKED);
    }
    return false;
}

static void vdac_pll_feedback(receiver_ctx_t *ctx, uint64_t *next_ns,
                              playback_state_t *play) {
    if (!ctx->vdac_clock_running || ctx->vdac_status == VDAC_FAULT) return;
    uint64_t ns = monotonic_ns();
    if (ns < *next_ns) return;
    *next_ns = ns + 100000000ULL; /* sample controller every 100 ms */
    int correction = vdac_pi_step(ctx, ns);
    if (vdac_check_sync(ctx, play, correction, ns)) return;
    if (ctx->feedback_pll) vdac_send_feedback(ctx, correction);
}

/* --- TCP reassembly --- */

static bool recv_exact_tcp(int fd, uint8_t *buf, size_t len, volatile bool *running) {
    size_t received = 0;
    while (received < len && *running) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 200);
        if (pr < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (pr == 0) continue;

        ssize_t n = recv(fd, buf + received, len - received, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        received += n;
    }
    return (received == len);
}

/* --- Wątek sieciowy --- */

static void *network_thread_fn(void *arg) {
    receiver_ctx_t *ctx = (receiver_ctx_t *)arg;
    uint8_t rx_buf[MAX_PACKET_SIZE];

    struct sched_param sp = { .sched_priority = 75 };
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);

    while (ctx->running) {
        ssize_t n = 0;

        if (ctx->mode == MODE_L2 || ctx->mode == MODE_UDP) {
            struct pollfd pfd = { .fd = ctx->sock_fd, .events = POLLIN };
            int pr = poll(&pfd, 1, 200);
            if (pr <= 0) {
                if (pr < 0 && errno == EINTR) continue;
                continue;
            }

            if (ctx->mode == MODE_L2) {
                socklen_t addr_len = sizeof(ctx->host_l2_addr);
                n = recvfrom(ctx->sock_fd, rx_buf, sizeof(rx_buf), 0,
                             (struct sockaddr *)&ctx->host_l2_addr, &addr_len);
                if (n > 0 && !ctx->host_mac_configured &&
                    addr_len >= offsetof(struct sockaddr_ll, sll_addr) + ETH_ALEN) {
                    ctx->has_host_addr = true;
                }
            } else {
                socklen_t addr_len = sizeof(ctx->host_udp_addr);
                n = recvfrom(ctx->sock_fd, rx_buf, sizeof(rx_buf), 0,
                             (struct sockaddr *)&ctx->host_udp_addr, &addr_len);
                if (n > 0) ctx->has_host_addr = true;
            }
        } else if (ctx->mode == MODE_TCP) {
            if (ctx->tcp_client_fd < 0) {
                struct pollfd pfd = { .fd = ctx->sock_fd, .events = POLLIN };
                int pr = poll(&pfd, 1, 200);
                if (pr <= 0) continue;

                socklen_t addr_len = sizeof(ctx->host_udp_addr);
                int client = accept(ctx->sock_fd, (struct sockaddr *)&ctx->host_udp_addr, &addr_len);
                if (client < 0) continue;

                int opt = 1;
                setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
                int rcvbuf = 4 * 1024 * 1024;
                setsockopt(client, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

                pthread_mutex_lock(&ctx->tcp_mutex);
                ctx->tcp_client_fd = client;
                ctx->has_host_addr = true;
                pthread_mutex_unlock(&ctx->tcp_mutex);
                printf("[NET-TCP] Polaczenie zaakceptowane.\n");
            }

            if (!recv_exact_tcp(ctx->tcp_client_fd, rx_buf, ctx->tcp_packet_size, &ctx->running)) {
                if (!ctx->running) break;
                printf("[NET-TCP] Polaczenie zamkniete. Oczekiwanie...\n");
                pthread_mutex_lock(&ctx->tcp_mutex);
                close(ctx->tcp_client_fd);
                ctx->tcp_client_fd = -1;
                ctx->has_host_addr = false;
                pthread_mutex_unlock(&ctx->tcp_mutex);
                usleep(50000);
                continue;
            }
            n = ctx->tcp_packet_size;
        }

        if (n <= 0) continue;
        DIAG_ADD(ctx, rx_packets, 1);
        DIAG_ADD(ctx, rx_wire_bytes, n);
        if (n < (ssize_t)SCREAM_HEADER_SIZE) {
            DIAG_ADD(ctx, short_packets, 1);
            continue;
        }

        scream_format_t fmt;
        if (!parse_scream_header(rx_buf, &fmt)) {
            DIAG_ADD(ctx, invalid_headers, 1);
            continue;
        }

        if (fmt.end_of_track) {
            printf("[STREAM] Odebrano znacznik konca utworu (end_of_track).\n");
            if (ctx->vdac_enabled)
                __atomic_store_n(&ctx->vdac_eot, true, __ATOMIC_RELEASE);
        }

        pthread_mutex_lock(&ctx->fmt_mutex);
        bool fmt_differs = (!ctx->fmt_initialized ||
            fmt.sample_rate != ctx->current_fmt.sample_rate ||
            fmt.sample_size != ctx->current_fmt.sample_size ||
            fmt.channels != ctx->current_fmt.channels ||
            fmt.is_dsd != ctx->current_fmt.is_dsd);

        if (fmt_differs) {
            ctx->pending_fmt = fmt;
            ctx->fmt_version++;
            __atomic_store_n(&ctx->fmt_change_requested, true, __ATOMIC_RELEASE);
            pthread_mutex_unlock(&ctx->fmt_mutex);

            while (__atomic_load_n(&ctx->fmt_change_requested, __ATOMIC_ACQUIRE) && ctx->running) {
                if (__atomic_load_n(&ctx->fmt_failed, __ATOMIC_ACQUIRE)) break;
                usleep(1000);
            }
        } else {
            pthread_mutex_unlock(&ctx->fmt_mutex);
        }

        if (__atomic_load_n(&ctx->fmt_failed, __ATOMIC_ACQUIRE)) continue;
        if (n == (ssize_t)SCREAM_HEADER_SIZE) continue;

        uint8_t *audio_payload = rx_buf + SCREAM_HEADER_SIZE;
        size_t audio_len = n - SCREAM_HEADER_SIZE;
        DIAG_ADD(ctx, rx_audio_bytes, audio_len);

        if (fmt.is_dsd && fmt.channels == 2 && audio_len >= 8) {
            dsd_deinterleave_fast(audio_payload, (audio_len / 8) * 8, ctx->dsd_swap_endian);
        }

        if (ring_push(&ctx->ring, audio_payload, audio_len)) {
            if (ctx->vdac_enabled) {
                __atomic_store_n(&ctx->vdac_last_rx_ms, monotonic_ms32(), __ATOMIC_RELAXED);
                if (!fmt.end_of_track)
                    __atomic_store_n(&ctx->vdac_eot, false, __ATOMIC_RELEASE);
            }
            DIAG_ADD(ctx, queued_audio_bytes, audio_len);
        } else {
            DIAG_ADD(ctx, ring_drop_packets, 1);
            DIAG_ADD(ctx, ring_drop_bytes, audio_len);
        }
    }

    pthread_mutex_lock(&ctx->tcp_mutex);
    if (ctx->tcp_client_fd >= 0) {
        close(ctx->tcp_client_fd);
        ctx->tcp_client_fd = -1;
    }
    pthread_mutex_unlock(&ctx->tcp_mutex);

    return NULL;
}

/* --- Zapis do ALSA (MMAP / RW) --- */

static inline void alsa_write_frames(receiver_ctx_t *ctx, size_t bpf) {
    if (ctx->use_mmap_active) {
        snd_pcm_sframes_t avail = snd_pcm_avail_update(ctx->pcm_handle);
        if (avail < 0) {
            DIAG_ADD(ctx, alsa_errors, 1);
            if (avail == -EPIPE) DIAG_ADD(ctx, alsa_xruns, 1);
            snd_pcm_recover(ctx->pcm_handle, avail, 0);
            return;
        }
        if (avail == 0) return;

        size_t ring_bytes = ring_available(&ctx->ring);
        snd_pcm_uframes_t ring_frames = ring_bytes / bpf;
        if (ring_frames == 0) return;

        snd_pcm_uframes_t frames = (ring_frames < (snd_pcm_uframes_t)avail) ? ring_frames : (snd_pcm_uframes_t)avail;

        while (frames > 0 && ctx->running) {
            const snd_pcm_channel_area_t *areas;
            snd_pcm_uframes_t offset;
            snd_pcm_uframes_t chunk = frames;

            int err = snd_pcm_mmap_begin(ctx->pcm_handle, &areas, &offset, &chunk);
            if (err < 0) {
                DIAG_ADD(ctx, alsa_errors, 1);
                if (err == -EPIPE) DIAG_ADD(ctx, alsa_xruns, 1);
                snd_pcm_recover(ctx->pcm_handle, err, 0);
                break;
            }
            if (chunk == 0) break;

            uint8_t *dma_dest = ((uint8_t *)areas[0].addr) + (offset * bpf);
            size_t bytes = chunk * bpf;

            ring_peek(&ctx->ring, dma_dest, bytes);
            __builtin_prefetch(dma_dest, 1, 3);

            snd_pcm_sframes_t committed = snd_pcm_mmap_commit(ctx->pcm_handle, offset, chunk);
            if (committed < 0 || (snd_pcm_uframes_t)committed != chunk) {
                DIAG_ADD(ctx, alsa_errors, 1);
                if (committed == -EPIPE) DIAG_ADD(ctx, alsa_xruns, 1);
                if (committed == -ENODEV) {
                    fprintf(stderr, "[ALSA] DAC odlaczony (-ENODEV)!\n");
                    snd_pcm_close(ctx->pcm_handle);
                    ctx->pcm_handle = NULL;
                    __atomic_store_n(&ctx->fmt_failed, true, __ATOMIC_RELEASE);
                } else {
                    snd_pcm_recover(ctx->pcm_handle, committed >= 0 ? -EPIPE : committed, 0);
                }
                break;
            }

            ring_consume(&ctx->ring, bytes);
            DIAG_ADD(ctx, alsa_frames_written, chunk);
            frames -= chunk;

            if (snd_pcm_state(ctx->pcm_handle) == SND_PCM_STATE_PREPARED)
                snd_pcm_start(ctx->pcm_handle);
        }
    } else {
        size_t avail = ring_available(&ctx->ring);
        size_t avail_aligned = (avail / bpf) * bpf;
        uint8_t chunk[8192];
        size_t cap = sizeof(chunk) - (sizeof(chunk) % bpf);
        if (avail_aligned > cap) avail_aligned = cap;

        size_t bytes = ring_pop(&ctx->ring, chunk, avail_aligned);
        if (bytes >= bpf) {
            snd_pcm_uframes_t total = bytes / bpf;
            snd_pcm_uframes_t done = 0;
            while (done < total && ctx->running) {
                snd_pcm_sframes_t n = snd_pcm_writei(ctx->pcm_handle,
                                                     chunk + done * bpf,
                                                     total - done);
                if (n < 0) {
                    if (n == -EINTR) continue;
                    DIAG_ADD(ctx, alsa_errors, 1);
                    if (n == -EPIPE) DIAG_ADD(ctx, alsa_xruns, 1);
                    DIAG_ADD(ctx, rw_discarded_frames, total - done);
                    if (n == -EPIPE) snd_pcm_prepare(ctx->pcm_handle);
                    else if (n == -ENODEV) {
                        fprintf(stderr, "[ALSA] DAC odlaczony (-ENODEV)!\n");
                        snd_pcm_close(ctx->pcm_handle);
                        ctx->pcm_handle = NULL;
                        __atomic_store_n(&ctx->fmt_failed, true, __ATOMIC_RELEASE);
                    } else {
                        snd_pcm_recover(ctx->pcm_handle, n, 0);
                    }
                    break;
                }
                done += n;
                DIAG_ADD(ctx, alsa_frames_written, n);
            }
        }
    }
}

/* --- Wątek ALSA --- */

static void *alsa_thread_fn(void *arg) {
    receiver_ctx_t *ctx = (receiver_ctx_t *)arg;

    struct sched_param sp = { .sched_priority = 85 };
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);

    playback_state_t state = STATE_PREFILLING;
    double ema_delay = 0.0;
    uint64_t pll_ticks = 0;
    uint64_t loop_ticks = 0;
    size_t last_logged_drops = 0;
    double last_diag_delay_check = 0.0;
    uint64_t vdac_next_feedback_ns = 0;

    while (ctx->running) {
        /* A repeated clock/transport fault is sticky until explicit restart,
         * even if the sender announces a new sample format. */
        if (ctx->vdac_enabled && ctx->vdac_status == VDAC_FAULT) {
            usleep(10000);
            continue;
        }
        bool need_reinit = __atomic_load_n(&ctx->fmt_change_requested, __ATOMIC_ACQUIRE) ||
                           (!ctx->vdac_enabled && !ctx->pcm_handle &&
                            !__atomic_load_n(&ctx->fmt_failed, __ATOMIC_ACQUIRE) && ctx->fmt_initialized);

        if (need_reinit) {
            state = STATE_PREFILLING;
            DIAG_ADD(ctx, discarded_on_reinit, ring_available(&ctx->ring));
            ring_clear_consumer(&ctx->ring);
            if (ctx->diag_enabled)
                __atomic_store_n(&ctx->diag.last_alsa_delay_frames, -1, __ATOMIC_RELAXED);
            ema_delay = 0.0;
            pll_ticks = 0;
            vdac_next_feedback_ns = 0;

            pthread_mutex_lock(&ctx->fmt_mutex);
            scream_format_t target = ctx->pending_fmt;
            uint32_t ver = ctx->fmt_version;
            pthread_mutex_unlock(&ctx->fmt_mutex);

            if (!(ctx->vdac_enabled ? vdac_init(ctx, &target) : reinit_alsa(ctx, &target))) {
                DIAG_ADD(ctx, format_failures, 1);
                __atomic_store_n(&ctx->fmt_failed, true, __ATOMIC_RELEASE);
                pthread_mutex_lock(&ctx->fmt_mutex);
                ctx->current_fmt = target;
                ctx->fmt_initialized = true;
                if (ctx->fmt_version == ver)
                    __atomic_store_n(&ctx->fmt_change_requested, false, __ATOMIC_RELEASE);
                pthread_mutex_unlock(&ctx->fmt_mutex);
                usleep(200000);
                continue;
            }

            DIAG_ADD(ctx, format_reinits, 1);
            __atomic_store_n(&ctx->fmt_failed, false, __ATOMIC_RELEASE);

            pthread_mutex_lock(&ctx->fmt_mutex);
            ctx->current_fmt = target;
            ctx->fmt_initialized = true;
            if (ctx->fmt_version == ver)
                __atomic_store_n(&ctx->fmt_change_requested, false, __ATOMIC_RELEASE);
            pthread_mutex_unlock(&ctx->fmt_mutex);
            continue;
        }

        /* On a single core SCHED_FIFO(85) must never busy-spin: the network
         * worker (SCHED_FIFO(75)) needs CPU to receive the very first packet. */
        if (!ctx->fmt_initialized || __atomic_load_n(&ctx->fmt_failed, __ATOMIC_ACQUIRE)) {
            usleep(ALSA_IDLE_SLEEP_US);
            continue;
        }

        size_t bytes_per_sample = (ctx->current_fmt.sample_size == 1) ? 4 : (ctx->current_fmt.sample_size / 8);
        size_t bpf = ctx->current_fmt.channels * bytes_per_sample;
        if (bpf == 0) bpf = 4;

        size_t avail = ring_available(&ctx->ring);
        size_t preload_required = ctx->preload_frames * bpf;
        if (preload_required > (RING_BUFFER_SIZE / 2))
            preload_required = RING_BUFFER_SIZE / 4;

        if (ctx->vdac_enabled) {
            /* This sink never opens ALSA. FAULT prevents repeated resets; a
             * process restart is an explicit recovery action by the operator. */
            if (ctx->vdac_status == VDAC_FAULT) {
                usleep(10000);
                continue;
            }
            if (state == STATE_PREFILLING) {
                size_t required_frames = ctx->preload_frames;
                if (required_frames > ctx->vdac_capacity) required_frames = ctx->vdac_capacity;
                if (required_frames < 1) required_frames = 1;
                if (avail / bpf >= required_frames) {
                    vdac_fill_from_ring(ctx, bpf);
                    vdac_start(ctx);
                    vdac_next_feedback_ns = 0;
                    state = STATE_PLAYING;
                }
            } else {
                if (vdac_drain_elapsed(ctx)) {
                    bool active = vdac_stream_recent(ctx);
                    if (active) DIAG_ADD(ctx, rebuffer_events, 1);
                    vdac_stop_and_prefill(ctx, &state, active,
                                          active ? "FIFO underflow" : "sender stopped / EOT");
                } else {
                    vdac_fill_from_ring(ctx, bpf);
                    vdac_pll_feedback(ctx, &vdac_next_feedback_ns, &state);
                }
            }
            usleep(ctx->vdac_tick_us);
            continue;
        }

        if (state == STATE_PREFILLING) {
            if (avail < preload_required) {
                /* We're waiting for NETWORK data, not ALSA free space.
                 * snd_pcm_wait() can return immediately for ALSA 'null' and
                 * starve the lower-priority network thread under SCHED_FIFO. */
                usleep(ALSA_IDLE_SLEEP_US);
                continue;
            }
            state = STATE_PLAYING;
        } else if (state == STATE_PLAYING) {
            if (avail < bpf) {
                state = STATE_PREFILLING;
                DIAG_ADD(ctx, rebuffer_events, 1);
                usleep(ALSA_IDLE_SLEEP_US);
                continue;
            }
        }

        loop_ticks++;

        size_t total_drops = __atomic_load_n(&ctx->ring.drop_count, __ATOMIC_RELAXED);
        if (total_drops != last_logged_drops && (loop_ticks % 100 == 0)) {
            printf("[RING] Przepelnienie: porzucono %zu pakietow (%zu B)\n",
                   total_drops,
                   __atomic_load_n(&ctx->ring.drop_bytes, __ATOMIC_RELAXED));
            last_logged_drops = total_drops;
        }

        /* ALSA calls remain in the ALSA thread (never in the reporter).
         * Delay is sampled only ~2 times/s while DIAG=1. */
        if (ctx->diag_enabled && (loop_ticks % 64 == 0) && ctx->pcm_handle) {
            struct timespec ts;
            if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
                double now = timespec_sec(&ts);
                if (now - last_diag_delay_check >= 0.5) {
                    snd_pcm_sframes_t d = 0;
                    if (snd_pcm_delay(ctx->pcm_handle, &d) == 0)
                        __atomic_store_n(&ctx->diag.last_alsa_delay_frames,
                                         (int)d, __ATOMIC_RELAXED);
                    last_diag_delay_check = now;
                }
            }
        }

        if (ctx->feedback_pll && ctx->has_host_addr && ctx->pcm_handle) {
            snd_pcm_sframes_t delay = 0;
            if (snd_pcm_delay(ctx->pcm_handle, &delay) == 0) {
                if (ctx->diag_enabled)
                    __atomic_store_n(&ctx->diag.last_alsa_delay_frames, (int)delay,
                                     __ATOMIC_RELAXED);
                ema_delay = (ema_delay == 0.0) ? delay : (0.95 * ema_delay + 0.05 * (double)delay);

                if (++pll_ticks % 50 == 0) {
                    snd_pcm_uframes_t buf_size = 4096;
                    snd_pcm_uframes_t period_size = 0;
                    /* Both output pointers must be valid for alsa-lib. */
                    snd_pcm_get_params(ctx->pcm_handle, &buf_size, &period_size);

                    long target_delay = buf_size / 2;
                    long error = (long)ema_delay - target_delay;
                    long deadband = buf_size / 20;

                    int feedback_ppm = 0;
                    if (error > deadband) {
                        feedback_ppm = -((error - deadband) * 80 / (long)target_delay);
                        if (feedback_ppm < -100) feedback_ppm = -100;
                    } else if (error < -deadband) {
                        feedback_ppm = -((error + deadband) * 80 / (long)target_delay);
                        if (feedback_ppm > 100) feedback_ppm = 100;
                    }

                    if (ctx->diag_enabled)
                        __atomic_store_n(&ctx->diag.last_feedback_ppm,
                                         feedback_ppm, __ATOMIC_RELAXED);
                    if (feedback_ppm != 0) {
                        struct scream_feedback_pkt fb;
                        fb.magic = htonl(SCREAM_FEEDBACK_MAGIC);
                        fb.ppm_drift = htonl(feedback_ppm);
                        ssize_t sent = -1;

                        if (ctx->mode == MODE_L2) {
                            sent = sendto(ctx->sock_fd, &fb, sizeof(fb), MSG_DONTWAIT,
                                          (struct sockaddr *)&ctx->host_l2_addr,
                                          sizeof(ctx->host_l2_addr));
                        } else if (ctx->mode == MODE_UDP) {
                            sent = sendto(ctx->sock_fd, &fb, sizeof(fb), MSG_DONTWAIT,
                                          (struct sockaddr *)&ctx->host_udp_addr,
                                          sizeof(ctx->host_udp_addr));
                        } else if (ctx->mode == MODE_TCP) {
                            pthread_mutex_lock(&ctx->tcp_mutex);
                            if (ctx->tcp_client_fd >= 0) {
                                sent = send(ctx->tcp_client_fd, &fb, sizeof(fb),
                                            MSG_DONTWAIT | MSG_NOSIGNAL);
                            }
                            pthread_mutex_unlock(&ctx->tcp_mutex);
                        }
                        if (sent == (ssize_t)sizeof(fb)) DIAG_ADD(ctx, feedback_sent, 1);
                    }
                }
            }
        }

        if (ctx->pcm_handle) {
            alsa_write_frames(ctx, bpf);
            snd_pcm_wait(ctx->pcm_handle, 20);
        } else {
            usleep(5000);
        }
    }

    if (ctx->pcm_handle) {
        snd_pcm_drop(ctx->pcm_handle);
        snd_pcm_close(ctx->pcm_handle);
        ctx->pcm_handle = NULL;
    }
    return NULL;
}

/* --- Inicjalizacja socketów --- */

/* SO_BUSY_POLL helpers. Zwraca 0 na sukces, -1 na blad lub brak wsparcia.
 * Wartosc 0 jest traktowana jako "wylacz" i zwraca 0 bez zmiany socketa. */
static int setup_busy_poll(int fd, int poll_us) {
    if (poll_us <= 0) return 0;

#ifdef SO_BUSY_POLL
    int v = poll_us;
    if (setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &v, sizeof(v)) != 0) {
        int err = errno;
        /* EPERM (brak CAP_NET_ADMIN) i ENOPROTOOPT (kernel bez wsparcia)
         * sa najczestszymi przypadkami - nie traktujemy jako blad krytyczny. */
        fprintf(stderr, "[NET] SO_BUSY_POLL(%d us) nie powiodlo sie: %s%s\n",
                poll_us, strerror(err),
                (err == EPERM) ? " (brak CAP_NET_ADMIN / roota?)" :
                (err == ENOPROTOOPT) ? " (kernel bez wsparcia)" : "");
        return -1;
    }
    /* Odczytaj efektywna wartosc - kernel moze zaokraglic lub zaokraglic w gore. */
    int got = 0;
    socklen_t glen = sizeof(got);
    if (getsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &got, &glen) == 0) {
        printf("[NET] SO_BUSY_POLL aktywne: zadane=%d us efektywne=%d us\n",
               poll_us, got);
    } else {
        printf("[NET] SO_BUSY_POLL aktywne (zadane=%d us)\n", poll_us);
    }

#ifdef SO_PREFER_BUSY_POLL
    /* Linux 5.11+: preferuj busy-poll nad softirq, aby watek odbierajacy
     * w pelni sterowal sciezka RX. Best-effort - brak wsparcia jest cichy
     * przy domyslnej verbosity. */
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_PREFER_BUSY_POLL, &one, sizeof(one)) == 0) {
        printf("[NET] SO_PREFER_BUSY_POLL wlaczone\n");
    } else {
        /* Kernel < 5.11 - nie jest to blad. */
    }
#endif
    return 0;
#else
    fprintf(stderr, "[NET] SO_BUSY_POLL nie jest wspierane przez te naglowki; "
            "UDP_BUSY_POLL_US=%d zignorowane.\n", poll_us);
    (void)fd;
    return -1;
#endif
}

static bool init_sockets(receiver_ctx_t *ctx) {
    if (ctx->mode == MODE_L2) {
        ctx->sock_fd = socket(AF_PACKET, SOCK_DGRAM, htons(ctx->eth_type));
        if (ctx->sock_fd < 0) {
            perror("[NET] socket(AF_PACKET)");
            return false;
        }

        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ctx->iface, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        if (ioctl(ctx->sock_fd, SIOCGIFINDEX, &ifr) < 0) {
            perror("[NET] SIOCGIFINDEX");
            close(ctx->sock_fd);
            return false;
        }

        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ctx->eth_type);

        if (bind(ctx->sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("[NET] bind(AF_PACKET)");
            close(ctx->sock_fd);
            return false;
        }

        if (ctx->host_mac_configured) {
            memset(&ctx->host_l2_addr, 0, sizeof(ctx->host_l2_addr));
            ctx->host_l2_addr.sll_family = AF_PACKET;
            ctx->host_l2_addr.sll_ifindex = ifr.ifr_ifindex;
            ctx->host_l2_addr.sll_protocol = htons(ctx->eth_type);
            ctx->host_l2_addr.sll_halen = ETH_ALEN;
            memcpy(ctx->host_l2_addr.sll_addr, ctx->static_host_mac, ETH_ALEN);
            ctx->has_host_addr = true;
            printf("[NET] Skonfigurowano statyczny MAC Hosta.\n");
        }

        printf("[NET] L2 Raw aktywny na %s (EtherType 0x%04X)\n", ctx->iface, ctx->eth_type);
        /* SO_BUSY_POLL ma inna semantyke dla AF_PACKET (wymaga
         * PACKET_QDISC_BYPASS i dziala tylko z PACKET_RX_RING); nie
         * stosujemy go dla L2 - tam jitter jest mniejszy niz przy UDP. */

    } else if (ctx->mode == MODE_UDP) {
        ctx->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (ctx->sock_fd < 0) {
            perror("[NET] socket(UDP)");
            return false;
        }

        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        serv_addr.sin_port = htons(ctx->port);

        if (bind(ctx->sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("[NET] bind(UDP)");
            close(ctx->sock_fd);
            return false;
        }

        /* SO_BUSY_POLL: tylko dla UDP (glowna sciezka). Wymaga roota
         * (CAP_NET_ADMIN). Na single-core RV1106 zostaw domyslnie 0 -
         * wlaczaj swiadomie z malym oknem (20-50 us). */
        if (ctx->udp_busy_poll_us > 0) {
            (void)setup_busy_poll(ctx->sock_fd, ctx->udp_busy_poll_us);
        }

        printf("[NET] UDP aktywny na porcie %d\n", ctx->port);

    } else if (ctx->mode == MODE_TCP) {
        ctx->sock_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (ctx->sock_fd < 0) {
            perror("[NET] socket(TCP)");
            return false;
        }

        int opt = 1;
        setsockopt(ctx->sock_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        serv_addr.sin_port = htons(ctx->port);

        if (bind(ctx->sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("[NET] bind(TCP)");
            close(ctx->sock_fd);
            return false;
        }

        if (listen(ctx->sock_fd, 1) < 0) {
            perror("[NET] listen(TCP)");
            close(ctx->sock_fd);
            return false;
        }

        printf("[NET] Serwer TCP nasluchuje na porcie %d (Pakiet: %zu B).\n",
               ctx->port, ctx->tcp_packet_size);
    }

    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(ctx->sock_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    int sndbuf = 256 * 1024;
    setsockopt(ctx->sock_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    return true;
}

/* --- main --- */

int main(int argc, char *argv[]) {
    memset(&g_ctx, 0, sizeof(g_ctx));

    g_ctx.mode = MODE_L2;
    strncpy(g_ctx.iface, "eth0", sizeof(g_ctx.iface) - 1);
    g_ctx.iface[sizeof(g_ctx.iface) - 1] = '\0';
    strncpy(g_ctx.alsa_device, "default", sizeof(g_ctx.alsa_device) - 1);
    g_ctx.alsa_device[sizeof(g_ctx.alsa_device) - 1] = '\0';
    g_ctx.port = 4011;
    g_ctx.eth_type = 0x88D8;
    g_ctx.feedback_pll = true;
    g_ctx.use_mmap_cfg = true;
    g_ctx.preload_frames = DEFAULT_PRELOAD_FRAMES;
    g_ctx.tcp_packet_size = DEFAULT_TCP_PKT_SIZE;
    g_ctx.dsd_rate_mult = 1;
    g_ctx.udp_busy_poll_us = 0; /* single-core: domyslnie OFF */
    g_ctx.diag_enabled = false; /* Avoid diagnostic overhead on target hardware. */
    g_ctx.diag_interval_ms = 1000;
    g_ctx.vdac_enabled = false; /* Always OFF on the real RV1106 by default. */
    g_ctx.vdac_rate_ppm = 0;
    g_ctx.vdac_buffer_frames = VDAC_DEFAULT_CAPACITY;
    g_ctx.vdac_tick_us = VDAC_DEFAULT_TICK_US;
    g_ctx.vdac_pi_enabled = true;
    g_ctx.vdac_kp = VDAC_DEFAULT_KP;
    g_ctx.vdac_ki = VDAC_DEFAULT_KI;
    g_ctx.vdac_max_correction_ppm = VDAC_MAX_CORRECTION_PPM;
    g_ctx.vdac_warn_hold_ms = 15000;
    g_ctx.vdac_resync_hold_ms = 750;
    g_ctx.vdac_resync_limit = 3;
    g_ctx.vdac_resync_window_s = 600;
    g_ctx.diag.last_alsa_delay_frames = -1;
    g_ctx.tcp_client_fd = -1;
    g_ctx.running = true;

    pthread_mutex_init(&g_ctx.tcp_mutex, NULL);
    pthread_mutex_init(&g_ctx.fmt_mutex, NULL);

    const char *custom_conf_path = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "c:h")) != -1) {
        switch (opt) {
            case 'c':
                custom_conf_path = optarg;
                break;
            case 'h':
            default:
                printf("Uzycie: %s [-c /sciezka/do/config.txt]\n", argv[0]);
                return 0;
        }
    }

    try_load_default_configs(&g_ctx, custom_conf_path);

    /* --- RLIMIT_MEMLOCK raise ---
     * Na Luckfox domyslny RLIMIT_MEMLOCK to czesto 64 KB. Bez podniesienia
     * limitu mlockall() zwroci sukces, ale faktycznie zablokuje tylko
     * pierwsze 64 KB - reszta (w tym 4 MB ring i bufory ALSA) moze byc
     * wywrocona na swap pod presja pamieci.
     *
     * Kolejnosc:
     *   1. getrlimit - sprawdz aktualny limit
     *   2. setrlimit - podnies do RLIM_INFINITY (best effort, wymaga
     *      CAP_SYS_RESOURCE / roota; jesli sie nie uda, mlockall i tak
     *      zablokuje tyle, ile pozwala limit)
     *   3. mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT)
     */
    {
        struct rlimit rl;
        if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
            if (rl.rlim_cur != RLIM_INFINITY || rl.rlim_max != RLIM_INFINITY) {
                struct rlimit want;
                want.rlim_cur = RLIM_INFINITY;
                want.rlim_max = RLIM_INFINITY;
                if (setrlimit(RLIMIT_MEMLOCK, &want) == 0) {
                    printf("[SYS] RLIMIT_MEMLOCK podniesiony do RLIM_INFINITY\n");
                } else {
                    fprintf(stderr,
                            "[SYS] Nie udalo sie podniesc RLIMIT_MEMLOCK: %s "
                            "(potrzebny root lub CAP_SYS_RESOURCE); mlockall "
                            "zablokuje tylko dostepny limit\n",
                            strerror(errno));
                }
            } else {
                printf("[SYS] RLIMIT_MEMLOCK juz RLIM_INFINITY\n");
            }
        } else {
            fprintf(stderr, "[SYS] getrlimit(RLIMIT_MEMLOCK) nie powiodlo sie: %s\n",
                    strerror(errno));
        }
    }

#ifndef MCL_ONFAULT
#define MCL_ONFAULT 4
#endif
    if (mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0) {
        int err = errno;
        if (mlockall(MCL_CURRENT) != 0) {
            fprintf(stderr,
                    "[SYS] Ostrzezenie: mlockall nie powiodlo sie (%s). "
                    "Dzialanie bez blokowania stron pamieci.\n",
                    strerror(err));
        } else {
            fprintf(stderr,
                    "[SYS] mlockall(MCL_ONFAULT) nieudane (%s), fallback do MCL_CURRENT OK\n",
                    strerror(err));
        }
    } else {
        printf("[SYS] mlockall(MCL_CURRENT|MCL_FUTURE|MCL_ONFAULT) aktywne\n");
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (!init_sockets(&g_ctx)) {
        pthread_mutex_destroy(&g_ctx.tcp_mutex);
        pthread_mutex_destroy(&g_ctx.fmt_mutex);
        return 1;
    }

    if (pthread_create(&g_ctx.net_thread, NULL, network_thread_fn, &g_ctx) != 0) {
        perror("[SYS] Blad tworzenia watku sieciowego");
        close(g_ctx.sock_fd);
        pthread_mutex_destroy(&g_ctx.tcp_mutex);
        pthread_mutex_destroy(&g_ctx.fmt_mutex);
        return 1;
    }
    if (pthread_create(&g_ctx.alsa_thread, NULL, alsa_thread_fn, &g_ctx) != 0) {
        perror("[SYS] Blad tworzenia watku ALSA");
        g_ctx.running = false;
        pthread_join(g_ctx.net_thread, NULL);
        close(g_ctx.sock_fd);
        pthread_mutex_destroy(&g_ctx.tcp_mutex);
        pthread_mutex_destroy(&g_ctx.fmt_mutex);
        return 1;
    }

    printf("[SYS] apscream-open v%s uruchomiony. Obsluga do 8ch@192k / 4ch@384k / 2ch@768k i DSD512.\n",
           AP_VERSION);
    if (g_ctx.udp_busy_poll_us > 0 && g_ctx.mode == MODE_UDP) {
        printf("[SYS] UDP busy-poll: %d us (single-core - monitor CPU!)\n",
               g_ctx.udp_busy_poll_us);
    }

    if (g_ctx.vdac_enabled) {
        printf("[VDAC] TEST-ONLY clock enabled; drift=%+d ppm, PI=%d "
               "kp=%.3f ki=%.4f max=+/- %d ppm, ALSA bypassed\n",
               g_ctx.vdac_rate_ppm, g_ctx.vdac_pi_enabled,
               g_ctx.vdac_kp, g_ctx.vdac_ki, g_ctx.vdac_max_correction_ppm);
        if (g_ctx.diag_enabled && g_ctx.vdac_csv_path[0]) {
            g_ctx.vdac_csv_file = fopen(g_ctx.vdac_csv_path, "w");
            if (!g_ctx.vdac_csv_file)
                fprintf(stderr, "[VDAC] Cannot open CSV '%s': %s\n",
                        g_ctx.vdac_csv_path, strerror(errno));
            else {
                fprintf(g_ctx.vdac_csv_file,
                        "elapsed_s,rate_hz,fifo_frames,fifo_capacity,state,"
                        "requested_ppm,p_ppm,i_ppm,rx_pkt_s,played_frames_s,"
                        "underflows,missing_frames,warnings,resyncs,faults\n");
                fflush(g_ctx.vdac_csv_file);
                printf("[VDAC] CSV: %s\n", g_ctx.vdac_csv_path);
            }
        }
        fflush(stdout);
    }
    if (g_ctx.diag_enabled) {
        printf("[DIAG] Wlaczono diagnostyke co %u ms; ring min/max probkowany co 100 ms.\n",
               g_ctx.diag_interval_ms);
        fflush(stdout);
    }
    struct timespec last_wall = {0}, last_cpu = {0};
    clock_gettime(CLOCK_MONOTONIC, &last_wall);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &last_cpu);
    size_t ring_min = ring_available(&g_ctx.ring);
    size_t ring_max = ring_min;
    while (g_ctx.running) {
        if (!g_ctx.diag_enabled) {
            sleep(1);
            continue;
        }
        usleep(100000);
        size_t occupied = ring_available(&g_ctx.ring);
        if (occupied < ring_min) ring_min = occupied;
        if (occupied > ring_max) ring_max = occupied;
        struct timespec wall = {0}, cpu = {0};
        clock_gettime(CLOCK_MONOTONIC, &wall);
        double elapsed = timespec_sec(&wall) - timespec_sec(&last_wall);
        if (elapsed * 1000.0 >= (double)g_ctx.diag_interval_ms) {
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu);
            double cpu_elapsed = timespec_sec(&cpu) - timespec_sec(&last_cpu);
            diag_report(&g_ctx, elapsed, cpu_elapsed, ring_min, ring_max);
            last_wall = wall;
            last_cpu = cpu;
            ring_min = ring_available(&g_ctx.ring);
            ring_max = ring_min;
        }
    }

    printf("[SYS] Zamykanie watkow...\n");
    pthread_join(g_ctx.net_thread, NULL);
    pthread_join(g_ctx.alsa_thread, NULL);

    if (g_ctx.sock_fd >= 0) close(g_ctx.sock_fd);
    pthread_mutex_destroy(&g_ctx.tcp_mutex);
    pthread_mutex_destroy(&g_ctx.fmt_mutex);
    if (g_ctx.vdac_csv_file) fclose(g_ctx.vdac_csv_file);

    return 0;
}