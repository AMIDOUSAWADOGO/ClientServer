#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/evp.h>

#define BUFFER_SIZE 4096

static const unsigned char AES_KEY[32] =
"0123456789abcdef0123456789abcdef";
static const unsigned char AES_IV[16] =
"abcdef9876543210";

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

/* ================= MAIN ================= */

int main(int argc, char *argv[]) {
    int sock;
    struct sockaddr_in server;
    char input[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE];

    if (argc != 3) {
        printf("Usage: %s <port> <ip>\n", argv[0]);
        return 1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);

    server.sin_family = AF_INET;
    server.sin_port = htons(atoi(argv[1]));
    inet_pton(AF_INET, argv[2], &server.sin_addr);

    connect(sock, (struct sockaddr *)&server, sizeof(server));
    printf("Connecté au serveur %s:%s\n", argv[2], argv[1]);

    while (1) {
        printf("> ");
        fgets(input, BUFFER_SIZE, stdin);
        input[strcspn(input, "\n")] = 0;

        int enc_len = aes_encrypt((unsigned char *)input, strlen(input), encrypted);
        uint32_t size = enc_len;

        send(sock, &size, sizeof(size), 0);
        send(sock, encrypted, enc_len, 0);

        recv(sock, &size, sizeof(size), 0);
        recv(sock, encrypted, size, 0);

        aes_decrypt(encrypted, size, decrypted);
        printf("[Server] : %s\n", decrypted);

        if (strcmp(input, "/quit") == 0) break;
    }

    close(sock);
    return 0;
}
