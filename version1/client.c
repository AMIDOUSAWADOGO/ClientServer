#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define SERVER_IP "127.0.0.1"
#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int sock;
    struct sockaddr_in serv_addr;
    char message[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];

    // Création de la socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Erreur socket");
        exit(EXIT_FAILURE);
    }

    // Configuration de l'adresse serveur
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Conversion IP
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("Adresse IP invalide");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Connexion au serveur
    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connexion échouée");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Connecté au serveur %s:%d\n", SERVER_IP, PORT);
    printf("Tapez votre message (/quit pour quitter)\n");

    // Boucle principale
    while (1) {
        printf("> ");
        fgets(message, BUFFER_SIZE, stdin);

        // Supprimer le \n
        message[strcspn(message, "\n")] = 0;

        // Envoi
        send(sock, message, strlen(message), 0);

        // Quit
        if (strcmp(message, "/quit") == 0) {
            memset(buffer, 0, BUFFER_SIZE);
            recv(sock, buffer, BUFFER_SIZE - 1, 0);
            printf("%s\n", buffer);
            break;
        }

        // Réception de l'écho
        memset(buffer, 0, BUFFER_SIZE);
        int bytes = recv(sock, buffer, BUFFER_SIZE - 1, 0);
        if (bytes <= 0) {
            printf("Connexion perdue.\n");
            break;
        }

        printf("[Server] : %s\n", buffer);
    }

    // Fermeture
    close(sock);
    printf("Client arrêté.\n");

    return 0;
}
