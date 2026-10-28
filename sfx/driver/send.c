/*************************************************************************
@File Name: mctp_send.c
@Desc: 
@Author: Andy-wei.hou
@Mail: wei.hou@scaleflux.com 
@Created Time: 2025年11月20日 星期四 20时28分53秒
@Log: 
************************************************************************/
// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/mctp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h> // Added for poll
#include <stdbool.h>
#include <signal.h>
#include "util.h"

#define DEST_EID  8
#define MCTP_CTRL_MSG_TYPE 0x00
#define MCTP_CTRL_CMD_SET_ENDPOINT_ID 0x01
#define MCTP_CTRL_CMD_GET_ENDPOINT_ID 0x02
#define PLDM_TYPE 0x01

/* -d/--dest-eid: the EID routed to the bridge instance under test */
static unsigned int g_dest_eid = DEST_EID;

static const char *completion_code_name(uint8_t cc)
{
    switch (cc) {
        case 0x00:
            return "Success";
        case 0x01:
            return "Error";
        case 0x02:
            return "Error Invalid Data";
        case 0x03:
            return "Error Invalid Length";
        case 0x04:
            return "Error Not Ready";
        case 0x05:
            return "Error Unspecified";
        case 0x80:
            return "Error Unsupported Cmd";
        default:
            return "Unknown";
    }
}


static const char *set_eid_op_name(uint8_t op)
{
    switch (op) {
        case 0x00:
            return "Set EID";
        case 0x01:
            return "Force EID";
        case 0x02:
            return "Reset EID";
        case 0x03:
            return "Set Discovered Flag";
        default:
            return "Unknown";
    }
}

static void print_ctrl_header(uint8_t hdr, uint8_t cmd)
{
    printf("MCTP ctrl hdr: raw=0x%02x rq=%u d=%u instance_id=%u cmd=0x%02x\n",
           hdr, (hdr >> 7) & 0x1, (hdr >> 6) & 0x1, hdr & 0x3f, cmd);
}

static volatile int g_sock = -1;

static void on_sigint(int sig)
{
    (void)sig;
    if (g_sock >= 0) {
        close(g_sock);
        g_sock = -1;
    }
    _exit(130);
}

int pldm_test(void);

static int mctp_ctrl_request(int sock, bool get_eid, uint8_t set_eid, uint8_t set_eid_op)
{
    struct sockaddr_mctp dst;
    uint8_t buf[64] = {0};
    ssize_t sent;

    buf[0] = 0x80;
    size_t req_len = 8;
    if (get_eid) {
        buf[1] = MCTP_CTRL_CMD_GET_ENDPOINT_ID;
        printf("Send MCTP control request: Get Endpoint ID\n");
    } else {
        buf[1] = MCTP_CTRL_CMD_SET_ENDPOINT_ID;
        buf[2] = set_eid_op;
        buf[3] = set_eid;
        printf("Send MCTP control request: %s -> %u\n",
               set_eid_op_name(set_eid_op), set_eid);
    }

    memset(&dst, 0, sizeof(dst));
    dst.smctp_family = AF_MCTP;
    dst.smctp_network = 1;
    dst.smctp_addr.s_addr = g_dest_eid;
    dst.smctp_type = MCTP_CTRL_MSG_TYPE;
    dst.smctp_tag = MCTP_TAG_OWNER;

    sent = sendto(sock, buf, req_len, 0,
                  (struct sockaddr*)&dst, sizeof(dst));
    if (sent < 0) {
        perror("sendto");
        return -1;
    }

    printf("Sent %zd bytes over AF_MCTP\n", sent);

    while (1) {
        struct pollfd fds[1];
        fds[0].fd = sock;
        fds[0].events = POLLIN;

        int ret = poll(fds, 1, 5000);
        if (ret < 0) {
            perror("poll");
            return -1;
        } else if (ret == 0) {
            printf("Timeout: no data received within 5 seconds\n");
            return -1;
        } else {
            uint8_t recv_buf[128];
            struct sockaddr_mctp from_addr;
            socklen_t from_len = sizeof(from_addr);

            ssize_t received = recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                                    (struct sockaddr*)&from_addr, &from_len);
            if (received < 0) {
                perror("recvfrom");
                return -1;
            } else {
                printf("Received %zd bytes from EID %u, msgType: 0x%02x\n",
                       received, from_addr.smctp_addr.s_addr, from_addr.smctp_type);
                printf("Data: ");
                print_hex(recv_buf, received);

                if (received >= 2 && from_addr.smctp_type == MCTP_CTRL_MSG_TYPE) {
                    print_ctrl_header(recv_buf[0], recv_buf[1]);
                    if (recv_buf[1] == MCTP_CTRL_CMD_SET_ENDPOINT_ID) {
                        if (received < 5) {
                            printf("Set Endpoint ID response too short\n");
                        } else {
                            printf("Completion code: 0x%02x (%s)\n",
                                   recv_buf[2], completion_code_name(recv_buf[2]));
                            printf("EID assignment status: 0x%02x\n", recv_buf[3]);
                            printf("EID allocation status: 0x%02x\n", recv_buf[4]);
                            if (received >= 6) {
                                printf("Assigned endpoint ID: %u\n", recv_buf[5]);
                            }
                            if (received >= 7) {
                                printf("Pool size: %u\n", recv_buf[6]);
                            }
                        }
                    } else if (recv_buf[1] == MCTP_CTRL_CMD_GET_ENDPOINT_ID) {
                        if (received < 5) {
                            printf("Get Endpoint ID response too short\n");
                        } else {
                            printf("Completion code: 0x%02x (%s)\n",
                                   recv_buf[2], completion_code_name(recv_buf[2]));
                            printf("Endpoint ID: %u\n", recv_buf[3]);
                            printf("Endpoint type / EID type: 0x%02x\n", recv_buf[4]);
                            if (received >= 6) {
                                printf("Medium-specific info: 0x%02x\n", recv_buf[5]);
                            }
                        }
                    }
                }
                /* One request, one response: done. */
                return 0;
            }
        }
    }
}

static int mctp_socket_bind(uint8_t msg_type)
{
    int sock;
    struct sockaddr_mctp src;

    sock = socket(AF_MCTP, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    memset(&src, 0, sizeof(src));
    src.smctp_family = AF_MCTP;
    src.smctp_network = MCTP_NET_ANY;
    src.smctp_addr.s_addr = MCTP_ADDR_ANY;
    src.smctp_type = msg_type;
    src.smctp_tag = MCTP_TAG_OWNER;

    if (bind(sock, (struct sockaddr*)&src, sizeof(src)) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }

    g_sock = sock;
    return sock;
}

static int mctp_ctrl_test(int argc, char **argv)
{
    unsigned int set_eid = DEST_EID;
    unsigned int set_eid_op = 0;
    bool get_eid = false;

    if (argc != 2 && argc != 3 && argc != 5) {
        fprintf(stderr, "Usage: %s [--get-eid] [--set-eid <eid>] [--op <0|1|2|3>]\n", argv[0]);
        return -1;
    }

    for (int i = 1; i < argc; ) {
        char *end = NULL;
        unsigned long value;

        if (strcmp(argv[i], "--get-eid") == 0) {
            get_eid = true;
            i++;
            continue;
        }

        if (i + 1 >= argc) {
            fprintf(stderr, "Usage: %s [--get-eid] [--set-eid <eid>] [--op <0|1|2|3>]\n", argv[0]);
            return -1;
        }

        if (strcmp(argv[i], "--set-eid") == 0) {
            value = strtoul(argv[i + 1], &end, 10);
            if (!argv[i + 1][0] || (end && *end) || value > 0xff) {
                fprintf(stderr, "Invalid EID '%s'\n", argv[i + 1]);
                return -1;
            }
            set_eid = (unsigned int)value;
        } else if (strcmp(argv[i], "--op") == 0) {
            value = strtoul(argv[i + 1], &end, 10);
            if (!argv[i + 1][0] || (end && *end) || value > 0x3) {
                fprintf(stderr, "Invalid SetEID op '%s'\n", argv[i + 1]);
                return -1;
            }
            set_eid_op = (unsigned int)value;
        } else {
            fprintf(stderr, "Usage: %s [--get-eid] [--set-eid <eid>] [--op <0|1|2|3>]\n", argv[0]);
            return -1;
        }

        i += 2;
    }

    int sock = mctp_socket_bind(MCTP_CTRL_MSG_TYPE);
    if (sock < 0) {
        return -1;
    }

    int ret = mctp_ctrl_request(sock, get_eid, (uint8_t)set_eid, (uint8_t)set_eid_op);

    close(sock);
    g_sock = -1;
    return ret;
}

int pldm_test(void) {
    int sock;
    struct sockaddr_mctp dst;
    uint8_t buf[64] = {0};
    ssize_t sent;
    size_t pldm_len = 20; // 示例 PLDM payload

    sock = mctp_socket_bind(PLDM_TYPE);
    if (sock < 0) {
        return -1;
    }


    // 3) 构造 payload
    /* arbitrary message to send, with message-type header */
    buf[0] = PLDM_TYPE;
    snprintf((char *)(buf + 1), sizeof(buf) - 1, "hello, world!");
    printf("%s\n", buf + 1);


    // 4) 设置目标地址
    memset(&dst, 0, sizeof(dst));
    dst.smctp_family = AF_MCTP;
    dst.smctp_network = 1;
    dst.smctp_addr.s_addr = g_dest_eid;
    dst.smctp_type = PLDM_TYPE;
    dst.smctp_tag = MCTP_TAG_OWNER;

    // 5) 发送
    sent = sendto(sock, buf, 1 + pldm_len, 0,
                  (struct sockaddr*)&dst, sizeof(dst));
    if (sent < 0) {
        perror("sendto");
        close(sock);
        g_sock = -1;
        return -1;
    }

    printf("Sent %zd bytes over AF_MCTP\n", sent);

    while (1) {
        // 6) 设置polling等待接收数据
        struct pollfd fds[1];
        fds[0].fd = sock;
        fds[0].events = POLLIN;

        int ret = poll(fds, 1, 5000); // 等待5秒
        if (ret < 0) {
            perror("poll");
            close(sock);
            g_sock = -1;
            return -1;
        } else if (ret == 0) {
            printf("Timeout: no data received within 5 seconds\n");
        } else {
            // 7) 接收数据
            uint8_t recv_buf[128] = {0};
            struct sockaddr_mctp from_addr;
            socklen_t from_len = sizeof(from_addr);

            ssize_t received = recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                                    (struct sockaddr*)&from_addr, &from_len);
            if (received < 0) {
                perror("recvfrom");
            } else {
                printf("Received %zd bytes from EID %u:, msgType: %x\n", received, from_addr.smctp_addr.s_addr
                    , from_addr.smctp_type);
                printf("Data: ");
                print_hex(recv_buf, received);

                // 如果数据是文本，也打印文本内容
                if (received > 0 && recv_buf[0] == PLDM_TYPE) {
                    printf("Text: %.*s\n", (int)received - 1, recv_buf + 1);
                }
            }
        }
    }

    close(sock);
    g_sock = -1;
    return 0;
}

/* Strip -d/--dest-eid <eid> from argv; returns the new argc or -1. */
static int take_dest_eid(int argc, char **argv)
{
    int out = 1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dest-eid") == 0) {
            char *end = NULL;
            unsigned long value;

            if (i + 1 >= argc)
                return -1;
            value = strtoul(argv[i + 1], &end, 10);
            if (!argv[i + 1][0] || (end && *end) || value == 0 || value > 0xfe) {
                fprintf(stderr, "Invalid destination EID '%s'\n", argv[i + 1]);
                return -1;
            }
            g_dest_eid = (unsigned int)value;
            i++;
            continue;
        }
        argv[out++] = argv[i];
    }
    argv[out] = NULL;
    return out;
}

int main(int argc, char **argv) {
    if (signal(SIGINT, on_sigint) == SIG_ERR) {
        perror("signal");
        return -1;
    }
    argc = take_dest_eid(argc, argv);
    if (argc < 0) {
        fprintf(stderr, "Usage: %s [-d <dest-eid>] [--get-eid] [--set-eid <eid>] [--op <0|1|2|3>]\n",
                argv[0]);
        return -1;
    }
    if (argc == 1) {
        return pldm_test();
    }
    return mctp_ctrl_test(argc, argv);
}
