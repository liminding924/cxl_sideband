#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <linux/mctp.h>
#include "pldm.h"
#include "mctp.h"
#include "cxl_cci.h"
#include "util.h"

#define DEVICE "/dev/mctp_bridge"
#define MAX_BUF 2048

#define DEV_EID 8
#define HOST_EID 19
#define MSG_TYPE_CONTROL 0

/* Overridable with --dev / --dev-eid / --host-eid, one bridge per instance */
static const char *g_device = DEVICE;
static uint8_t g_dev_eid = DEV_EID;
static uint8_t g_host_eid = HOST_EID;

uint8_t cur_tag = 0;
int g_fd = 0;

static volatile sig_atomic_t g_running = 1;
static int g_udp_fd = -1;

static void cleanup_all(void)
{
    if (g_udp_fd >= 0) {
        close(g_udp_fd);
        g_udp_fd = -1;
    }
    if (g_fd > 0) {
        close(g_fd);
        g_fd = -1;
    }
}

static void on_signal(int sig)
{
    g_running = 0;
}

static void setup_signals(void)
{
    struct sigaction sa = {0};
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/*
 * Peer link to the device-side forwarder (cxl_test_tool).
 *
 * UDP mode: one datagram == one MCTP frame (legacy, lossy over WAN).
 * TCP mode: byte stream, every MCTP frame is prefixed with a 2-byte
 *           big-endian length so frame boundaries survive TCP segmentation
 *           and retransmission. The link auto-reconnects when it drops.
 */
#define TCP_FRAME_HDR_LEN   2
#define TCP_RECONNECT_SEC   1
#define TCP_CONNECT_TIMEOUT_MS 3000

struct udp_config {
    bool enabled;
    bool tcp;
    bool connected;
    int sockfd;
    struct sockaddr_storage target_addr;
    socklen_t target_addrlen;
    uint16_t listen_port;
    char target[256];                      /* host:port for TCP reconnect */
    uint8_t rx_buf[TCP_FRAME_HDR_LEN + MAX_BUF];
    size_t rx_len;
    time_t next_connect;
};

static const char *peer_name(const struct udp_config *cfg)
{
    return cfg->tcp ? "TCP" : "UDP";
}

struct control_request {
    bool enabled;
    uint8_t opcode;
    uint8_t data[MAX_BUF];
    int data_len;
};

static void print_usage(const char *prog)
{
    printf("Usage: %s [--udp host:port --listen-port port | --tcp host:port [--listen-port port]]\n"
           "          [--no-bridge] [--once] [--control ctrl-opc] [--control-data \"hex bytes\"]\n"
           "          [--dev path] [--dev-eid eid] [--host-eid eid]\n"
           "  --udp  legacy datagram link, one datagram per MCTP frame\n"
           "  --tcp  reliable stream link, 2-byte length-prefixed MCTP frames, auto-reconnect\n"
           "  --dev  mctp_bridge char device (default " DEVICE "); run one bridge per\n"
           "         device, e.g. /dev/mctp_bridge1 for netdev mctp_bridge1\n"
           "  --dev-eid / --host-eid  EIDs for --control and typed frames (default %d / %d)\n",
           prog, DEV_EID, HOST_EID);
}

static int parse_eid(const char *s, uint8_t *eid)
{
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 0);

    if (!*s || *end || v > 0xff)
        return -1;
    *eid = (uint8_t)v;
    return 0;
}

static int parse_port(const char *s, uint16_t *port)
{
    char *end = NULL;
    long value = strtol(s, &end, 10);

    if (!s[0] || (end && *end) || value <= 0 || value > 65535)
        return -1;

    *port = (uint16_t)value;
    return 0;
}

static int parse_udp_target(const char *arg, char *host, size_t host_len, uint16_t *port)
{
    const char *sep = strrchr(arg, ':');
    size_t len;

    if (!sep || sep == arg)
        return -1;

    len = (size_t)(sep - arg);
    if (len == 0 || len >= host_len)
        return -1;

    memcpy(host, arg, len);
    host[len] = '\0';

    return parse_port(sep + 1, port);
}

static int bind_local_port(int sockfd, int family, uint16_t listen_port)
{
    int one = 1;

    if (listen_port == 0)
        return 0;

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    if (family == AF_INET) {
        struct sockaddr_in local = {0};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port = htons(listen_port);
        return bind(sockfd, (struct sockaddr *)&local, sizeof(local));
    }
    if (family == AF_INET6) {
        struct sockaddr_in6 local6 = {0};
        local6.sin6_family = AF_INET6;
        local6.sin6_addr = in6addr_any;
        local6.sin6_port = htons(listen_port);
        return bind(sockfd, (struct sockaddr *)&local6, sizeof(local6));
    }
    return 0;
}

/* Non-blocking connect with a bounded wait so an unreachable peer cannot
 * stall the bridge for the kernel's full SYN retry budget. */
static int connect_with_timeout(int sockfd, const struct sockaddr *addr,
                                socklen_t addrlen, int timeout_ms)
{
    int flags = fcntl(sockfd, F_GETFL, 0);
    int ret;

    if (flags < 0)
        return -1;
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    ret = connect(sockfd, addr, addrlen);
    if (ret < 0 && errno == EINPROGRESS) {
        struct pollfd pfd = { .fd = sockfd, .events = POLLOUT };
        int soerr = 0;
        socklen_t soerr_len = sizeof(soerr);

        ret = poll(&pfd, 1, timeout_ms);
        if (ret <= 0) {
            if (ret == 0)
                errno = ETIMEDOUT;
            ret = -1;
        } else if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &soerr, &soerr_len) < 0) {
            ret = -1;
        } else if (soerr != 0) {
            errno = soerr;
            ret = -1;
        } else {
            ret = 0;
        }
    }

    if (fcntl(sockfd, F_SETFL, flags) < 0)
        return -1;
    return ret;
}

static void peer_disconnect(struct udp_config *cfg, const char *why)
{
    if (cfg->sockfd >= 0) {
        close(cfg->sockfd);
        cfg->sockfd = -1;
    }
    g_udp_fd = -1;
    cfg->connected = false;
    cfg->rx_len = 0;
    cfg->next_connect = time(NULL) + TCP_RECONNECT_SEC;
    printf("[%s LINK DOWN] %s; reconnect in %ds\n", peer_name(cfg), why, TCP_RECONNECT_SEC);
}

/* Resolve cfg->target and open the socket. Works for both transports;
 * for TCP it also performs the connect handshake. */
static int peer_connect(struct udp_config *cfg)
{
    struct addrinfo hints = {0};
    struct addrinfo *result = NULL;
    struct addrinfo *rp;
    char host[256];
    uint16_t target_port;
    char port_str[16];
    int sockfd = -1;
    int ret;

    if (parse_udp_target(cfg->target, host, sizeof(host), &target_port) < 0) {
        fprintf(stderr, "Invalid %s target '%s', expected host:port\n",
                peer_name(cfg), cfg->target);
        return -1;
    }

    snprintf(port_str, sizeof(port_str), "%u", target_port);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = cfg->tcp ? SOCK_STREAM : SOCK_DGRAM;

    ret = getaddrinfo(host, port_str, &hints, &result);
    if (ret != 0) {
        fprintf(stderr, "getaddrinfo(%s): %s\n", host, gai_strerror(ret));
        return -1;
    }

    for (rp = result; rp; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0)
            continue;

        if (bind_local_port(sockfd, rp->ai_family, cfg->listen_port) < 0) {
            close(sockfd);
            sockfd = -1;
            continue;
        }

        if (cfg->tcp) {
            int one = 1;
            setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
            ret = connect_with_timeout(sockfd, rp->ai_addr, rp->ai_addrlen,
                                       TCP_CONNECT_TIMEOUT_MS);
        } else {
            ret = connect(sockfd, rp->ai_addr, rp->ai_addrlen);
        }

        if (ret == 0) {
            memcpy(&cfg->target_addr, rp->ai_addr, rp->ai_addrlen);
            cfg->target_addrlen = rp->ai_addrlen;
            cfg->sockfd = sockfd;
            cfg->connected = true;
            cfg->rx_len = 0;
            g_udp_fd = sockfd;
            break;
        }

        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(result);

    if (sockfd < 0) {
        fprintf(stderr, "%s connect to %s failed: %s\n", peer_name(cfg),
                cfg->target, strerror(errno));
        cfg->next_connect = time(NULL) + TCP_RECONNECT_SEC;
        return -1;
    }

    printf("[%s LINK UP] target=%s listen_port=%u\n", peer_name(cfg),
           cfg->target, cfg->listen_port);
    return 0;
}

static int udp_init(struct udp_config *cfg, const char *target,
                    uint16_t listen_port, bool tcp)
{
    cfg->tcp = tcp;
    cfg->listen_port = listen_port;
    cfg->sockfd = -1;
    cfg->enabled = true;
    snprintf(cfg->target, sizeof(cfg->target), "%s", target);

    if (!tcp)
        return peer_connect(cfg);

    /* TCP: the device-side tool may not be up yet; keep trying until the
     * link is established or we are asked to stop. */
    while (g_running) {
        if (peer_connect(cfg) == 0)
            return 0;
        sleep(TCP_RECONNECT_SEC);
    }
    return -1;
}

/* Called from the main loop while a TCP link is down. */
static void peer_maybe_reconnect(struct udp_config *cfg)
{
    if (!cfg->tcp || cfg->connected)
        return;
    if (time(NULL) < cfg->next_connect)
        return;
    peer_connect(cfg);
}

static int send_all(int sockfd, const uint8_t *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t w = send(sockfd, buf + off, len - off, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)w;
    }
    return (int)len;
}

static void print_mctp_meta(const char *prefix, const uint8_t *buf, int len)
{
    if (len < (int)sizeof(struct mctp_hdr) + 1) {
        printf("[%s meta] short frame len=%d\n", prefix, len);
        return;
    }

    const struct mctp_hdr *hdr = (const struct mctp_hdr *)buf;
    uint8_t msg_type = buf[sizeof(struct mctp_hdr)];
    uint8_t flags = hdr->flags_seq_tag;
    uint8_t tag = flags & 0x7;
    uint8_t seq = (flags >> 4) & 0x3;
    uint8_t to = (flags >> 3) & 0x1;

    printf("[%s meta] ver=0x%02x dst_eid=%u src_eid=%u flags=0x%02x tag=%u seq=%u to=%u msg_type=0x%02x payload_len=%d\n",
           prefix, hdr->ver, hdr->dst, hdr->src, flags, tag, seq, to,
           msg_type, len - (int)sizeof(struct mctp_hdr) - 1);

    if (msg_type == MSG_TYPE_PLDM && len >= (int)sizeof(struct mctp_hdr) + 1 + 3) {
        const uint8_t *pldm = buf + sizeof(struct mctp_hdr) + 1;
        uint8_t hdr0 = pldm[0];
        printf("[%s pldm] hdr=0x%02x rq=%u d=%u instance_id=%u type=0x%02x cmd=0x%02x\n",
               prefix, hdr0, (hdr0 >> 7) & 0x1, (hdr0 >> 6) & 0x1,
               hdr0 & 0x1f, pldm[1], pldm[2]);
    }
}

int handle_cci_req(unsigned char *buf, int len)
{
    struct mctp_hdr *hdr = (struct mctp_hdr *)buf;
    uint8_t tmp_eid = hdr->dst;
    hdr->dst = hdr->src;
    hdr->src = tmp_eid;
    hdr->flags_seq_tag &= 0xF7;

    struct cxlmi_cci_msg *cci_msg = (struct cxlmi_cci_msg *)(buf + sizeof(struct mctp_hdr) + 1);

    printf("cci command [0x%x 0x%x]\n", cci_msg->command_set, cci_msg->command);

    cci_msg->return_code = 0;
    cci_msg->category = 1;

    return write_to_host(buf, len);
}

int handle_req_from_host(uint8_t *buf, int len)
{
    struct mctp_hdr *hdr = (struct mctp_hdr *)buf;
    uint8_t msg_type = *(buf + sizeof(struct mctp_hdr));
    char *payload = (char *)(buf + sizeof(struct mctp_hdr) + 1);
    printf("mctp hdr[ver: %x, dst: %x, src:%x, flags_tag: %x], msg_type: %x, len: %x]\n",
           hdr->ver, hdr->dst, hdr->src, hdr->flags_seq_tag, msg_type, len);
    cur_tag = hdr->flags_seq_tag;

    if (msg_type == MSG_TYPE_PLDM) {
        printf("PLDM message received, handling PLDM request\n");
        return handle_pldm_req(buf, len);
    } else if (msg_type == MSG_TYPE_CXLCCI) {
        printf("CXLCCI message received, handling CCI request\n");
        return handle_cci_req(buf, len);
    }

    printf("Non-PLDM message type: 0x%02x\n", msg_type);
    print_hex((const uint8_t *)payload, len - (int)sizeof(struct mctp_hdr) - 1);
    return 0;
}

int write_to_host(uint8_t *out_buf, int len)
{
    if (g_fd <= 0) {
        printf("device not opened\n");
        return -1;
    }

    printf("[SEND TO HOST %d bytes]\n", len);
    print_mctp_meta("SEND TO HOST", out_buf, len);
    print_hex(out_buf, len);
    int w = write(g_fd, out_buf, len);
    if (w < 0)
        perror("write");
    return w;
}

static int udp_forward_to_peer(struct udp_config *cfg, uint8_t *buf, int len)
{
    char label[32];
    int sent;

    snprintf(label, sizeof(label), "FORWARD TO %s", peer_name(cfg));

    if (cfg->tcp) {
        uint8_t hdr[TCP_FRAME_HDR_LEN];

        if (!cfg->connected) {
            printf("[%s DROP %d bytes] link down\n", label, len);
            return -1;
        }
        if (len <= 0 || len > MAX_BUF) {
            printf("[%s DROP %d bytes] bad frame length\n", label, len);
            return -1;
        }

        hdr[0] = (uint8_t)((len >> 8) & 0xff);
        hdr[1] = (uint8_t)(len & 0xff);
        if (send_all(cfg->sockfd, hdr, sizeof(hdr)) < 0 ||
            send_all(cfg->sockfd, buf, (size_t)len) < 0) {
            perror("tcp send");
            peer_disconnect(cfg, "send failed");
            return -1;
        }
        sent = len;
    } else {
        sent = send(cfg->sockfd, buf, len, 0);
        if (sent < 0) {
            perror("udp send");
            return -1;
        }
    }

    printf("[%s %d bytes]\n", label, sent);
    print_mctp_meta(label, buf, sent);
    print_hex(buf, sent);
    return sent;
}

static int send_control_request(int fd, struct udp_config *udp, bool no_bridge,
                                const struct control_request *control)
{
    uint8_t out_buf[MAX_BUF] = {0};
    struct mctp_hdr *hdr = (struct mctp_hdr *)out_buf;
    int len;

    if (!control->enabled)
        return 0;

    hdr->ver = 0x01;
    hdr->dst = g_dev_eid;
    hdr->src = g_host_eid;
    hdr->flags_seq_tag = 0xC8;
    out_buf[4] = MSG_TYPE_CONTROL;
    out_buf[5] = 0x80;
    out_buf[6] = control->opcode;
    if (control->data_len > 0)
        memcpy(out_buf + 7, control->data, control->data_len);
    len = 7 + control->data_len;

    printf("[SEND CONTROL %d bytes]\n", len);
    print_hex(out_buf, len);

    if (udp->enabled)
        return udp_forward_to_peer(udp, out_buf, len);
    if (no_bridge) {
        printf("[NO-BRIDGE] skip write_to_host\n");
        return len;
    }
    return write(fd, out_buf, len);
}

static int deliver_peer_frame(struct udp_config *cfg, uint8_t *buf, int n, bool no_bridge)
{
    char label[32];

    snprintf(label, sizeof(label), "RECV FROM %s", peer_name(cfg));
    printf("[%s %d bytes]\n", label, n);
    print_mctp_meta(label, buf, n);
    print_hex(buf, n);
    if (no_bridge) {
        printf("[MOCK BRIDGE RX %d bytes]\n", n);
        print_hex(buf, n);
        printf("[NO-BRIDGE] skip write_to_host\n");
        return n;
    }
    return write_to_host(buf, n);
}

/* Returns <0 only on a fatal error; a dropped TCP link is handled by
 * scheduling a reconnect and returning 0. */
static int udp_forward_to_bridge(struct udp_config *cfg, bool no_bridge)
{
    if (!cfg->tcp) {
        uint8_t buf[MAX_BUF];
        int n = recv(cfg->sockfd, buf, sizeof(buf), 0);

        if (n < 0) {
            perror("udp recv");
            return -1;
        }
        if (n == 0)
            return 0;
        return deliver_peer_frame(cfg, buf, n, no_bridge);
    }

    ssize_t n = recv(cfg->sockfd, cfg->rx_buf + cfg->rx_len,
                     sizeof(cfg->rx_buf) - cfg->rx_len, 0);
    if (n < 0) {
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
            return 0;
        perror("tcp recv");
        peer_disconnect(cfg, "recv failed");
        return 0;
    }
    if (n == 0) {
        peer_disconnect(cfg, "peer closed");
        return 0;
    }
    cfg->rx_len += (size_t)n;

    /* Reassemble length-prefixed frames; a partial frame stays buffered. */
    while (cfg->rx_len >= TCP_FRAME_HDR_LEN) {
        size_t flen = ((size_t)cfg->rx_buf[0] << 8) | cfg->rx_buf[1];

        if (flen == 0 || flen > MAX_BUF) {
            fprintf(stderr, "tcp frame length %zu out of range, resetting link\n", flen);
            peer_disconnect(cfg, "framing error");
            return 0;
        }
        if (cfg->rx_len < TCP_FRAME_HDR_LEN + flen)
            break;

        if (deliver_peer_frame(cfg, cfg->rx_buf + TCP_FRAME_HDR_LEN, (int)flen, no_bridge) < 0)
            return -1;

        cfg->rx_len -= TCP_FRAME_HDR_LEN + flen;
        if (cfg->rx_len)
            memmove(cfg->rx_buf, cfg->rx_buf + TCP_FRAME_HDR_LEN + flen, cfg->rx_len);
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct udp_config udp = {0};
    struct control_request control = {0};
    const char *udp_target = NULL;
    const char *control_data = NULL;
    uint16_t listen_port = 0;
    bool use_tcp = false;
    bool no_bridge = false;
    bool once = false;
    int fd = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--udp") == 0 || strcmp(argv[i], "--tcp") == 0) {
            if (i + 1 >= argc || udp_target != NULL) {
                print_usage(argv[0]);
                return 1;
            }
            use_tcp = (argv[i][2] == 't');
            udp_target = argv[++i];
        } else if (strcmp(argv[i], "--listen-port") == 0) {
            if (i + 1 >= argc || parse_port(argv[i + 1], &listen_port) < 0) {
                print_usage(argv[0]);
                return 1;
            }
            i++;
        } else if (strcmp(argv[i], "--no-bridge") == 0) {
            no_bridge = true;
        } else if (strcmp(argv[i], "--once") == 0) {
            once = true;
        } else if (strcmp(argv[i], "--control") == 0) {
            unsigned int opcode;
            if (i + 1 >= argc || sscanf(argv[i + 1], "%x", &opcode) != 1 || opcode > 0xff) {
                print_usage(argv[0]);
                return 1;
            }
            control.enabled = true;
            control.opcode = (uint8_t)opcode;
            i++;
        } else if (strcmp(argv[i], "--control-data") == 0) {
            if (i + 1 >= argc) {
                print_usage(argv[0]);
                return 1;
            }
            control_data = argv[++i];
        } else if (strcmp(argv[i], "--dev") == 0) {
            if (i + 1 >= argc) {
                print_usage(argv[0]);
                return 1;
            }
            g_device = argv[++i];
        } else if (strcmp(argv[i], "--dev-eid") == 0 || strcmp(argv[i], "--host-eid") == 0) {
            uint8_t *eid = (argv[i][2] == 'd') ? &g_dev_eid : &g_host_eid;

            if (i + 1 >= argc || parse_eid(argv[i + 1], eid) < 0) {
                print_usage(argv[0]);
                return 1;
            }
            i++;
        } else {
            print_usage(argv[0]);
            return 1;
        }
    }

    if (!use_tcp && (udp_target != NULL) != (listen_port != 0)) {
        fprintf(stderr, "Both --udp and --listen-port are required for UDP mode\n");
        return 1;
    }

    if (control_data) {
        control.data_len = parse_hex_string(control_data, control.data, sizeof(control.data));
        if (control.data_len < 0) {
            fprintf(stderr, "Invalid control data format. Example: 08 00\n");
            return 1;
        }
    }

    if (!no_bridge) {
        fd = open(g_device, O_RDWR);
        if (fd < 0) {
            if (errno == EBUSY)
                fprintf(stderr, "open %s: busy, another bridge already serves it\n", g_device);
            else
                perror("open");
            return 1;
        }
        g_fd = fd;
        printf("Opened %s successfully.\n", g_device);
        printf("Waiting for incoming MCTP frames via poll() ...\n");
    } else {
        printf("Running in no-bridge mode.\n");
    }

    atexit(cleanup_all);
    setup_signals();

    if (udp_target && udp_init(&udp, udp_target, listen_port, use_tcp) < 0) {
        if (fd >= 0)
            close(fd);
        return 1;
    }

    if (send_control_request(fd, &udp, no_bridge, &control) < 0)
        return 1;

    if (!udp.enabled || no_bridge)
        printf("You can also type hex bytes to send (ex: 01 02 FF 33):\n");

    while (g_running) {
        struct pollfd pfds[2];
        nfds_t nfds = 0;
        int udp_index = -1;
        int ret;

        peer_maybe_reconnect(&udp);

        if (fd >= 0) {
            pfds[nfds].fd = fd;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            nfds++;
        }

        if (udp.enabled && udp.connected) {
            udp_index = (int)nfds;
            pfds[nfds].fd = udp.sockfd;
            pfds[nfds].events = POLLIN;
            pfds[nfds].revents = 0;
            nfds++;
        }

        ret = poll(pfds, nfds, 500);
        if (ret < 0) {
            if (errno == EINTR || !g_running)
                break;
            perror("poll");
            break;
        }

        if (fd >= 0 && ret > 0 && (pfds[0].revents & POLLIN)) {
            uint8_t buf[MAX_BUF];
            int n = read(fd, buf, sizeof(buf));
            if (n < 0) {
                perror("read");
                break;
            }

            printf("\n[RECV %d bytes]:\n", n);
            print_mctp_meta("RECV FROM HOST", buf, n);
            print_hex(buf, n);
            if (udp.enabled)
                udp_forward_to_peer(&udp, buf, n);
            else
                handle_req_from_host(buf, n);
            if (once)
                break;
        }

        if (udp_index >= 0 && ret > 0 &&
            (pfds[udp_index].revents & (POLLIN | POLLHUP | POLLERR))) {
            if (udp_forward_to_bridge(&udp, no_bridge) < 0)
                break;
            if (once)
                break;
        }

        if (!udp.enabled || no_bridge) {
            fd_set rfds;
            struct timeval tv = {0, 0};
            FD_ZERO(&rfds);
            FD_SET(0, &rfds);

            int has_input = select(1, &rfds, NULL, NULL, &tv);
            if (has_input > 0 && FD_ISSET(0, &rfds)) {
                char line[4096];
                uint8_t out_buf[MAX_BUF];
                struct mctp_hdr *hdr = (struct mctp_hdr *)out_buf;
                int len;

                if (!fgets(line, sizeof(line), stdin))
                    break;

                if (udp.enabled && no_bridge) {
                    len = parse_hex_string(line, out_buf, sizeof(out_buf));
                    if (len < 0) {
                        printf("Invalid hex format. Example: 01 02 FF A0\n");
                        continue;
                    }

                    printf("[SEND %s %d bytes]\n", peer_name(&udp), len);
                    print_hex(out_buf, len);
                    udp_forward_to_peer(&udp, out_buf, len);
                    if (once)
                        break;
                    continue;
                }

                memset(out_buf, 0, sizeof(out_buf));
                hdr->ver = 0x01;
                hdr->dst = g_host_eid;
                hdr->src = g_dev_eid;
                hdr->flags_seq_tag = cur_tag & 0xF7;
                out_buf[4] = MSG_TYPE_PLDM;

                len = parse_hex_string(line, out_buf + 5, sizeof(out_buf) - 5);
                if (len < 0) {
                    printf("Invalid hex format. Example: 01 02 FF A0\n");
                    continue;
                }
                len += 5;

                printf("[SEND %d bytes]\n", len);
                print_hex(out_buf, len);

                int w = write(fd, out_buf, len);
                if (w < 0)
                    perror("write");
            }
        }
    }

    if (udp.enabled && udp.sockfd >= 0) {
        close(udp.sockfd);
        udp.sockfd = -1;
        g_udp_fd = -1;
    }
    g_fd = -1;
    if (fd >= 0)
        close(fd);
    return 0;
}
