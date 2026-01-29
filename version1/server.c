#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    char buffer[BUFFER_SIZE];

    // Création de la socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1) {
        perror("Erreur socket");
        exit(EXIT_FAILURE);
    }

    // Configuration de l'adresse
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Liaison
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Erreur bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Mise en écoute
    if (listen(server_fd, 3) < 0) {
        perror("Erreur listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Serveur en écoute sur le port %d...\n", PORT);

    // Acceptation de la connexion
    client_fd = accept(server_fd, (struct sockaddr*)&address, &addrlen);
    if (client_fd < 0) {
        perror("Erreur accept");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Client connecté.\n");

    // Boucle principale
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);

        int bytes = recv(client_fd, buffer, BUFFER_SIZE - 1, 0);
        if (bytes <= 0) {
            printf("Client déconnecté.\n");
            break;
        }

        printf("Message reçu : %s\n", buffer);

        // Commande /quit
        if (strcmp(buffer, "/quit") == 0) {
            send(client_fd, "[Server] : You will be terminated", 34, 0);
            break;
        }

        // Echo
        send(client_fd, buffer, strlen(buffer), 0);
    }

    // Fermeture
    close(client_fd);
    close(server_fd);

    printf("Serveur arrêté.\n");
    return 0;
}
