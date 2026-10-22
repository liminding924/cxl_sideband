#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "util.h"

#define MAX_BUF 2048

static void print_usage(const char *prog)
{
    printf("Usage: %s --listen <port>\n", prog);
}

int main(int argc, char **argv)
{
    int sockfd;
    struct sockaddr_in addr = {0};

    if (argc != 3 || strcmp(argv[1], "--listen") != 0) {
        print_usage(argv[0]);
        return 1;
    }

    int port = atoi(argv[2]);
    if (port <= 0 || port > 65535) {
        print_usage(argv[0]);
        return 1;
    }

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    printf("Listening on UDP port %d\n", port);

    while (1) {
        uint8_t buf[MAX_BUF];
        struct sockaddr_in peer = {0};
        socklen_t peer_len = sizeof(peer);
        char peer_ip[INET_ADDRSTRLEN];
        int n = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&peer, &peer_len);
        if (n < 0) {
            perror("recvfrom");
            break;
        }

        if (!inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip)))
            strcpy(peer_ip, "unknown");

        printf("[RECV %d bytes from %s:%u]\n", n, peer_ip, ntohs(peer.sin_port));
        print_hex(buf, n);

        if (sendto(sockfd, buf, n, 0, (struct sockaddr *)&peer, peer_len) < 0) {
            perror("sendto");
            break;
        }

        printf("[ECHO %d bytes]\n", n);
    }

    close(sockfd);
    return 0;
}
