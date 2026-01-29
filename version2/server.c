#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/evp.h>

#define MAX_CLIENTS 20
#define BUFFER_SIZE 4096

static const unsigned char AES_KEY[32] =
"0123456789abcdef0123456789abcdef";
static const unsigned char AES_IV[16] =
"abcdef9876543210";

int client_count = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
    int sock;
} client_t;

/* ================= CRYPTO ================= */

int aes_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *ciphertext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, AES_IV);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int aes_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *plaintext) {

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, AES_KEY, AES_IV);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    plaintext[plaintext_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

/* ================= CLIENT HANDLER ================= */

void *handle_client(void *arg) {
    client_t *cli = (client_t *)arg;
    unsigned char buffer[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE];

    while (1) {
        uint32_t size;
        int r = recv(cli->sock, &size, sizeof(size), 0);
        if (r <= 0) break;

        recv(cli->sock, buffer, size, 0);
        aes_decrypt(buffer, size, decrypted);

        if (strcmp((char *)decrypted, "/quit") == 0) {
            char msg[] = "You will be terminated";
            int enc_len = aes_encrypt((unsigned char *)msg, strlen(msg), encrypted);
            uint32_t s = enc_len;
            send(cli->sock, &s, sizeof(s), 0);
            send(cli->sock, encrypted, enc_len, 0);
            break;
        }

        int enc_len = aes_encrypt(decrypted, strlen((char *)decrypted), encrypted);
        uint32_t s = enc_len;
        send(cli->sock, &s, sizeof(s), 0);
        send(cli->sock, encrypted, enc_len, 0);
    }

    close(cli->sock);
    free(cli);

    pthread_mutex_lock(&mutex);
    client_count--;
    pthread_mutex_unlock(&mutex);

    pthread_exit(NULL);
}

/* ================= MAIN ================= */

int main(int argc, char *argv[]) {
    int server_fd, client_fd;
    struct sockaddr_in server, client;
    socklen_t len = sizeof(client);
    pthread_t tid;

    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        return 1;
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(atoi(argv[1]));

    bind(server_fd, (struct sockaddr *)&server, sizeof(server));
    listen(server_fd, MAX_CLIENTS);

    printf("Server est en ecoute sur le port %s...\n", argv[1]);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client, &len);

        pthread_mutex_lock(&mutex);
        if (client_count >= MAX_CLIENTS) {
            close(client_fd);
            pthread_mutex_unlock(&mutex);
            continue;
        }
        client_count++;
        pthread_mutex_unlock(&mutex);

        client_t *cli = malloc(sizeof(client_t));
        cli->sock = client_fd;

        pthread_create(&tid, NULL, handle_client, cli);
        pthread_detach(tid);
    }
}
