#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/aes.h>
#include <sys/select.h>

#define BUFFER_SIZE 1024
#define AES_KEY_STR "0123456789abcdef0123456789abcdef" // 32 octets = AES-256

void aes_encrypt(const unsigned char *input, unsigned char *output, int len) {
    AES_KEY key;
    AES_set_encrypt_key((unsigned char*)AES_KEY_STR, 256, &key);
    for (int i = 0; i < len; i += AES_BLOCK_SIZE)
        AES_encrypt(input+i, output+i, &key);
}

void aes_decrypt(const unsigned char *input, unsigned char *output, int len) {
    AES_KEY key;
    AES_set_decrypt_key((unsigned char*)AES_KEY_STR, 256, &key);
    for (int i = 0; i < len; i += AES_BLOCK_SIZE)
        AES_decrypt(input+i, output+i, &key);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <port> <server_ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);
    char *ip = argv[2];

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); exit(EXIT_FAILURE); }

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server.sin_addr);

    if (connect(sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
        perror("connect"); exit(EXIT_FAILURE);
    }

    printf("Connecté au serveur %s:%d\n", ip, port);

    fd_set readfds;
    char input[BUFFER_SIZE];
    unsigned char buffer[BUFFER_SIZE];

    while (1) {
       
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);
        int maxfd = sock;

        if (select(maxfd+1, &readfds, NULL, NULL, NULL) < 0) { perror("select"); continue; }

        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            fgets(input, BUFFER_SIZE, stdin);
            input[strcspn(input, "\n")] = 0;

            unsigned char enc[BUFFER_SIZE] = {0};
            int aes_len = ((strlen(input)+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;
            aes_encrypt((unsigned char*)input, enc, aes_len);
            send(sock, enc, aes_len, 0);

            if (strcmp(input, "/quit") == 0) break;
        }

        if (FD_ISSET(sock, &readfds)) {
            memset(buffer, 0, BUFFER_SIZE);
            int bytes = recv(sock, buffer, BUFFER_SIZE, 0);
            if (bytes <= 0) { printf("Serveur déconnecté.\n"); break; }

            unsigned char dec[BUFFER_SIZE] = {0};
            aes_decrypt(buffer, dec, bytes);
            dec[BUFFER_SIZE-1] = '\0';
            printf("%s\n", dec);
        }
    }

    close(sock);
    return 0;
}
