#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <openssl/aes.h>

#define MAX_CLIENTS 20
#define BUFFER_SIZE 1024
#define MAX_NICK 32
#define AES_KEY_STR "0123456789abcdef0123456789abcdef" // 32 octets = AES-256

typedef struct {
    int socket;
    char nickname[MAX_NICK];
    int is_registered;
} Client;

Client clients[MAX_CLIENTS];

/* ---------- AES Symmetric Encryption/Decryption ---------- */
void aes_encrypt(const unsigned char *input, unsigned char *output, int len) {
    AES_KEY key;
    AES_set_encrypt_key((unsigned char*)AES_KEY_STR, 256, &key);
    for (int i = 0; i < len; i += AES_BLOCK_SIZE) {
        AES_encrypt(input + i, output + i, &key);
    }
}

void aes_decrypt(const unsigned char *input, unsigned char *output, int len) {
    AES_KEY key;
    AES_set_decrypt_key((unsigned char*)AES_KEY_STR, 256, &key);
    for (int i = 0; i < len; i += AES_BLOCK_SIZE) {
        AES_decrypt(input + i, output + i, &key);
    }
}

/* ---------- Client management ---------- */
void init_clients() {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i].socket = 0;
        clients[i].is_registered = 0;
        clients[i].nickname[0] = '\0';
    }
}

/* ---------- Main Server ---------- */
int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);
    int server_fd, max_fd;
    struct sockaddr_in address;
    fd_set readfds;
    unsigned char buffer[BUFFER_SIZE];

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) { perror("socket"); exit(EXIT_FAILURE); }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind"); exit(EXIT_FAILURE);
    }

    if (listen(server_fd, MAX_CLIENTS) < 0) {
        perror("listen"); exit(EXIT_FAILURE);
    }

    init_clients();
    printf("Serveur V3 en écoute sur le port %d...\n", port);

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(server_fd, &readfds);
        max_fd = server_fd;

        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i].socket > 0) {
                FD_SET(clients[i].socket, &readfds);
                if (clients[i].socket > max_fd) max_fd = clients[i].socket;
            }
        }

        if (select(max_fd + 1, &readfds, NULL, NULL, NULL) < 0) { perror("select"); continue; }

        /* Nouvelle connexion */
        if (FD_ISSET(server_fd, &readfds)) {
            int new_socket = accept(server_fd, NULL, NULL);
            int added = 0;

            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].socket == 0) {
                    clients[i].socket = new_socket;
                    clients[i].is_registered = 0;
                    clients[i].nickname[0] = '\0';

                    unsigned char welcome[BUFFER_SIZE] = {0};
                    strncpy((char*)welcome, "[Server] : Bienvenue. Utilisez /nick <pseudo>\n", BUFFER_SIZE-1);

                    int aes_len = ((strlen((char*)welcome)+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;
                    unsigned char enc[BUFFER_SIZE] = {0};
                    aes_encrypt(welcome, enc, aes_len);
                    send(new_socket, enc, aes_len, 0);

                    added = 1;
                    break;
                }
            }
            if (!added) {
                char *msg = "Server cannot accept incoming connections anymore.\n";
                send(new_socket, msg, strlen(msg), 0);
                close(new_socket);
            }
        }

        /* Messages clients */
        for (int i = 0; i < MAX_CLIENTS; i++) {
            int sd = clients[i].socket;
            if (sd > 0 && FD_ISSET(sd, &readfds)) {
                memset(buffer, 0, BUFFER_SIZE);
                int bytes = recv(sd, buffer, BUFFER_SIZE, 0);
                if (bytes <= 0) {
                    close(sd);
                    clients[i].socket = 0;
                    clients[i].is_registered = 0;
                    clients[i].nickname[0] = '\0';
                    continue;
                }

                unsigned char decrypted[BUFFER_SIZE] = {0};
                aes_decrypt(buffer, decrypted, bytes);
                decrypted[BUFFER_SIZE-1] = '\0';
                char *msg = (char*)decrypted;

                /* /quit */
                if (strcmp(msg, "/quit") == 0) {
                    unsigned char out[BUFFER_SIZE] = {0};
                    strncpy((char*)out,"[Server] : You will be terminated\n",BUFFER_SIZE-1);
                    int aes_len = ((strlen((char*)out)+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;
                    unsigned char enc[BUFFER_SIZE] = {0};
                    aes_encrypt(out, enc, aes_len);
                    send(sd, enc, aes_len, 0);

                    close(sd);
                    clients[i].socket = 0;
                    clients[i].is_registered = 0;
                    clients[i].nickname[0] = '\0';
                    continue;
                }

                /* /nick */
                if (strncmp(msg, "/nick ", 6) == 0) {
                    char *nick = msg + 6;
                    strncpy(clients[i].nickname, nick, MAX_NICK-1);
                    clients[i].nickname[MAX_NICK-1] = '\0';
                    clients[i].is_registered = 1;

                    unsigned char out[BUFFER_SIZE] = {0};
                    strncpy((char*)out,"[Server] : Pseudo enregistré\n",BUFFER_SIZE-1);
                    int aes_len = ((strlen((char*)out)+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;
                    unsigned char enc[BUFFER_SIZE] = {0};
                    aes_encrypt(out, enc, aes_len);
                    send(sd, enc, aes_len, 0);
                    continue;
                }

                /* Pas identifié */
                if (!clients[i].is_registered) {
                    unsigned char out[BUFFER_SIZE] = {0};
                    strncpy((char*)out,"[Server] : Identifiez-vous avec /nick\n",BUFFER_SIZE-1);
                    int aes_len = ((strlen((char*)out)+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;
                    unsigned char enc[BUFFER_SIZE] = {0};
                    aes_encrypt(out, enc, aes_len);
                    send(sd, enc, aes_len, 0);
                    continue;
                }

                /* /who */
                if (strcmp(msg, "/who") == 0) {
                    char list[BUFFER_SIZE] = "Utilisateurs connectés:\n";
                    int len = strlen(list);
                    for (int j = 0; j < MAX_CLIENTS; j++) {
                        if (clients[j].socket > 0 && clients[j].is_registered) {
                            len += snprintf(list + len, BUFFER_SIZE - len, "- %s\n", clients[j].nickname);
                        }
                    }
                    int aes_len = ((len+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;
                    unsigned char enc[BUFFER_SIZE] = {0};
                    aes_encrypt((unsigned char*)list, enc, aes_len);
                    send(sd, enc, aes_len, 0);
                    continue;
                }

                /* /whois */
                if (strncmp(msg, "/whois ", 7) == 0) {
                    char *nick = msg + 7;
                    int found = 0;
                    for (int j = 0; j < MAX_CLIENTS; j++) {
                        if (clients[j].is_registered && strcmp(clients[j].nickname, nick) == 0) {
                            char info[BUFFER_SIZE];
                            snprintf(info,BUFFER_SIZE,"[Server] : %s | socket fd = %d\n",nick,clients[j].socket);
                            int aes_len = ((strlen(info)+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;
                            unsigned char enc[BUFFER_SIZE] = {0};
                            aes_encrypt((unsigned char*)info, enc, aes_len);
                            send(sd, enc, aes_len,0);
                            found = 1;
                            break;
                        }
                    }
                    if (!found) {
                        unsigned char out[BUFFER_SIZE] = {0};
                        strncpy((char*)out,"[Server] : Utilisateur introuvable\n",BUFFER_SIZE-1);
                        int aes_len = ((strlen((char*)out)+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;
                        unsigned char enc[BUFFER_SIZE] = {0};
                        aes_encrypt(out, enc, aes_len);
                        send(sd, enc, aes_len,0);
                    }
                    continue;
                }

                /* Echo */
                int aes_len = ((strlen(msg)+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;
                unsigned char enc[BUFFER_SIZE] = {0};
                aes_encrypt((unsigned char*)msg, enc, aes_len);
                send(sd, enc, aes_len, 0);
            }
        }
    }

    close(server_fd);
    return 0;
}
