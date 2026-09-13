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

#define AP_VERSION "3.2-SINGLE-CORE-RV1106"

#define MAX_PACKET_SIZE       9216
#define RING_BUFFER_SIZE      (4 * 1024 * 1024)
#define RING_BUFFER_MASK      (RING_BUFFER_SIZE - 1)
#define SCREAM_HEADER_SIZE    5
#define SCREAM_FEEDBACK_MAGIC 0x53434642
#define DEFAULT_TCP_PKT_SIZE  1157
#define DEFAULT_PRELOAD_FRAMES 4096

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
    size_t wp = r->write_pos;
    size_t rp = r->read_pos;
    return (wp - rp) & RING_BUFFER_MASK;
}

static inline size_t ring_free_space(spsc_ring_t *r) {
    return (RING_BUFFER_SIZE - 1) - ring_available(r);
}

static inline void ring_clear_consumer(spsc_ring_t *r) {
    r->read_pos = r->write_pos;
    __sync_synchronize();
}

static inline void ring_push(spsc_ring_t *r, const uint8_t *data, size_t len) {
    size_t free_sp = ring_free_space(r);
    if (len > free_sp) {
        r->drop_count++;
        r->drop_bytes += len;
        return;
    }
    size_t wp = r->write_pos;
    size_t first = RING_BUFFER_SIZE - wp;
    if (first >= len) {
        memcpy(r->buffer + wp, data, len);
    } else {
        memcpy(r->buffer + wp, data, first);
        memcpy(r->buffer, data + first, len - first);
    }
    __sync_synchronize();
    r->write_pos = (wp + len) & RING_BUFFER_MASK;
}

static inline size_t ring_peek(spsc_ring_t *r, uint8_t *dest, size_t len) {
    size_t avail = ring_available(r);
    if (avail < len) len = avail;
    if (len == 0) return 0;

    size_t rp = r->read_pos;
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
    size_t rp = r->read_pos;
    __sync_synchronize();
    r->read_pos = (rp + len) & RING_BUFFER_MASK;
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
    snd_pcm_get_params(ctx->pcm_handle, &buf_frames, NULL);
    if (buf_frames && frames > buf_frames)
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

        if (n < (ssize_t)SCREAM_HEADER_SIZE) continue;

        scream_format_t fmt;
        if (!parse_scream_header(rx_buf, &fmt)) continue;

        if (fmt.end_of_track) {
            printf("[STREAM] Odebrano znacznik konca utworu (end_of_track).\n");
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

        if (fmt.is_dsd && fmt.channels == 2 && audio_len >= 8) {
            dsd_deinterleave_fast(audio_payload, (audio_len / 8) * 8, ctx->dsd_swap_endian);
        }

        ring_push(&ctx->ring, audio_payload, audio_len);
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

    while (ctx->running) {
        bool need_reinit = __atomic_load_n(&ctx->fmt_change_requested, __ATOMIC_ACQUIRE) ||
                           (!ctx->pcm_handle && !__atomic_load_n(&ctx->fmt_failed, __ATOMIC_ACQUIRE) && ctx->fmt_initialized);

        if (need_reinit) {
            state = STATE_PREFILLING;
            ring_clear_consumer(&ctx->ring);
            ema_delay = 0.0;
            pll_ticks = 0;

            pthread_mutex_lock(&ctx->fmt_mutex);
            scream_format_t target = ctx->pending_fmt;
            uint32_t ver = ctx->fmt_version;
            pthread_mutex_unlock(&ctx->fmt_mutex);

            if (!reinit_alsa(ctx, &target)) {
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

            __atomic_store_n(&ctx->fmt_failed, false, __ATOMIC_RELEASE);

            pthread_mutex_lock(&ctx->fmt_mutex);
            ctx->current_fmt = target;
            ctx->fmt_initialized = true;
            if (ctx->fmt_version == ver)
                __atomic_store_n(&ctx->fmt_change_requested, false, __ATOMIC_RELEASE);
            pthread_mutex_unlock(&ctx->fmt_mutex);
            continue;
        }

        if (!ctx->fmt_initialized || __atomic_load_n(&ctx->fmt_failed, __ATOMIC_ACQUIRE))
            continue;

        size_t bytes_per_sample = (ctx->current_fmt.sample_size == 1) ? 4 : (ctx->current_fmt.sample_size / 8);
        size_t bpf = ctx->current_fmt.channels * bytes_per_sample;
        if (bpf == 0) bpf = 4;

        size_t avail = ring_available(&ctx->ring);
        size_t preload_required = ctx->preload_frames * bpf;
        if (preload_required > (RING_BUFFER_SIZE / 2))
            preload_required = RING_BUFFER_SIZE / 4;

        if (state == STATE_PREFILLING) {
            if (avail < preload_required) {
                if (ctx->pcm_handle) snd_pcm_wait(ctx->pcm_handle, 20);
                else usleep(5000);
                continue;
            }
            state = STATE_PLAYING;
        } else if (state == STATE_PLAYING) {
            if (avail < bpf) {
                state = STATE_PREFILLING;
                continue;
            }
        }

        loop_ticks++;

        if (ctx->ring.drop_count != last_logged_drops && (loop_ticks % 100 == 0)) {
            printf("[RING] Przepelnienie: porzucono %zu pakietow (%zu B)\n",
                   ctx->ring.drop_count, ctx->ring.drop_bytes);
            last_logged_drops = ctx->ring.drop_count;
        }

        if (ctx->feedback_pll && ctx->has_host_addr && ctx->pcm_handle) {
            snd_pcm_sframes_t delay = 0;
            if (snd_pcm_delay(ctx->pcm_handle, &delay) == 0) {
                ema_delay = (ema_delay == 0.0) ? delay : (0.95 * ema_delay + 0.05 * (double)delay);

                if (++pll_ticks % 50 == 0) {
                    snd_pcm_uframes_t buf_size = 4096;
                    snd_pcm_get_params(ctx->pcm_handle, &buf_size, NULL);

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

                    if (feedback_ppm != 0) {
                        struct scream_feedback_pkt fb;
                        fb.magic = htonl(SCREAM_FEEDBACK_MAGIC);
                        fb.ppm_drift = htonl(feedback_ppm);

                        if (ctx->mode == MODE_L2) {
                            sendto(ctx->sock_fd, &fb, sizeof(fb), MSG_DONTWAIT,
                                   (struct sockaddr *)&ctx->host_l2_addr, sizeof(ctx->host_l2_addr));
                        } else if (ctx->mode == MODE_UDP) {
                            sendto(ctx->sock_fd, &fb, sizeof(fb), MSG_DONTWAIT,
                                   (struct sockaddr *)&ctx->host_udp_addr, sizeof(ctx->host_udp_addr));
                        } else if (ctx->mode == MODE_TCP) {
                            pthread_mutex_lock(&ctx->tcp_mutex);
                            if (ctx->tcp_client_fd >= 0) {
                                send(ctx->tcp_client_fd, &fb, sizeof(fb), MSG_DONTWAIT | MSG_NOSIGNAL);
                            }
                            pthread_mutex_unlock(&ctx->tcp_mutex);
                        }
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

    while (g_ctx.running) {
        sleep(1);
    }

    printf("[SYS] Zamykanie watkow...\n");
    pthread_join(g_ctx.net_thread, NULL);
    pthread_join(g_ctx.alsa_thread, NULL);

    if (g_ctx.sock_fd >= 0) close(g_ctx.sock_fd);
    pthread_mutex_destroy(&g_ctx.tcp_mutex);
    pthread_mutex_destroy(&g_ctx.fmt_mutex);

    return 0;
}
