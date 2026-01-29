#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <openssl/aes.h>
#include <fcntl.h>

#define MAX_CLIENTS 20
#define MAX_SALONS 10
#define MAX_NICK 32
#define BUFFER_SIZE 1024
#define AES_KEY_STR "0123456789abcdef0123456789abcdef"

typedef struct {
    int socket;
    char nickname[MAX_NICK];
    int is_registered;
    char salon[MAX_NICK];
} Client;

typedef struct {
    char name[MAX_NICK];
    int members[MAX_CLIENTS];
    int member_count;
} Salon;

Client clients[MAX_CLIENTS];
Salon salons[MAX_SALONS];

/* ---------- AES Encryption ---------- */
void aes_encrypt(const unsigned char *input, unsigned char *output, int len) {
    AES_KEY key;
    AES_set_encrypt_key((unsigned char*)AES_KEY_STR, 256, &key);
    for (int i=0;i<len;i+=AES_BLOCK_SIZE) AES_encrypt(input+i, output+i, &key);
}

void aes_decrypt(const unsigned char *input, unsigned char *output, int len) {
    AES_KEY key;
    AES_set_decrypt_key((unsigned char*)AES_KEY_STR, 256, &key);
    for (int i=0;i<len;i+=AES_BLOCK_SIZE) AES_decrypt(input+i, output+i, &key);
}

/* ---------- Client & Salon Management ---------- */
void init_clients() {
    for (int i=0;i<MAX_CLIENTS;i++){
        clients[i].socket=0; clients[i].is_registered=0;
        clients[i].nickname[0]='\0'; clients[i].salon[0]='\0';
    }
}

void init_salons() {
    for(int i=0;i<MAX_SALONS;i++){
        salons[i].name[0]='\0'; salons[i].member_count=0;
        for(int j=0;j<MAX_CLIENTS;j++) salons[i].members[j]=-1;
    }
}

int find_salon(const char *name){
    for(int i=0;i<MAX_SALONS;i++) if(strcmp(salons[i].name,name)==0) return i;
    return -1;
}

int add_client_to_salon(int client_index, const char *salon_name){
    int idx=find_salon(salon_name);
    if(idx<0){
        for(int i=0;i<MAX_SALONS;i++){
            if(salons[i].name[0]=='\0'){ strcpy(salons[i].name,salon_name); idx=i; break;}
        }
        if(idx<0) return -1;
    }
    for(int j=0;j<salons[idx].member_count;j++) if(salons[idx].members[j]==client_index) return idx;
    salons[idx].members[salons[idx].member_count++]=client_index;
    strcpy(clients[client_index].salon,salon_name);
    return idx;
}

void remove_client_from_salon(int client_index){
    char *salon_name=clients[client_index].salon;
    if(salon_name[0]=='\0') return;
    int idx=find_salon(salon_name); if(idx<0) return;
    int new_count=0;
    for(int j=0;j<salons[idx].member_count;j++){
        if(salons[idx].members[j]!=client_index) salons[idx].members[new_count++]=salons[idx].members[j];
    }
    salons[idx].member_count=new_count;
    clients[client_index].salon[0]='\0';
    if(salons[idx].member_count==0) salons[idx].name[0]='\0';
}

/* ---------- Messaging ---------- */
void send_to_client(int client_index, const char *msg){
    unsigned char out[BUFFER_SIZE]={0};
    int len=strlen(msg);
    int aes_len=((len+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;
    aes_encrypt((unsigned char*)msg,out,aes_len);
    send(clients[client_index].socket,out,aes_len,0);
}

void broadcast(int sender_index, const char *msg){
    for(int i=0;i<MAX_CLIENTS;i++){
        if(i!=sender_index && clients[i].socket>0 && clients[i].is_registered) send_to_client(i,msg);
    }
}

void send_salon(int sender_index,const char *msg){
    char *salon_name=clients[sender_index].salon;
    if(salon_name[0]=='\0') return;
    int idx=find_salon(salon_name); if(idx<0) return;
    for(int j=0;j<salons[idx].member_count;j++){
        int ci=salons[idx].members[j];
        if(ci!=sender_index) send_to_client(ci,msg);
    }
}

/* ---------- File Transfer ---------- */
void send_file(int sender_index, int receiver_index, const char *filename){
    send_to_client(receiver_index,"[Server] : Demande de réception de fichier. Acceptez ? (yes/no)");
    unsigned char buffer[BUFFER_SIZE]={0};
    int bytes=recv(clients[receiver_index].socket,buffer,BUFFER_SIZE,0);
    unsigned char dec[BUFFER_SIZE]={0};
    aes_decrypt(buffer,dec,bytes);
    dec[BUFFER_SIZE-1]='\0';
    if(strcmp((char*)dec,"yes")!=0){
        send_to_client(sender_index,"[Server] : Transfert refusé");
        send_to_client(receiver_index,"[Server] : Transfert annulé");
        return;
    }

    FILE *f=fopen(filename,"rb");
    if(!f){ send_to_client(sender_index,"[Server] : Fichier introuvable"); return; }

    send_to_client(sender_index,"[Server] : Transfert en cours...");
    char chunk[BUFFER_SIZE];
    int n;
    while((n=fread(chunk,1,BUFFER_SIZE,f))>0){
        unsigned char enc[BUFFER_SIZE]={0};
        int aes_len=((n+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;
        aes_encrypt((unsigned char*)chunk,enc,aes_len);
        send(clients[receiver_index].socket,enc,aes_len,0);
    }
    fclose(f);
    send_to_client(sender_index,"[Server] : Transfert terminé");
    send_to_client(receiver_index,"[Server] : Fichier reçu avec succès");
}

/* ---------- Main Server ---------- */
int main(int argc,char *argv[]){
    if(argc!=2){ printf("Usage: %s <port>\n",argv[0]); exit(EXIT_FAILURE);}
    int port=atoi(argv[1]);
    int server_fd,max_fd;
    struct sockaddr_in address;
    fd_set readfds;
    unsigned char buffer[BUFFER_SIZE];

    server_fd=socket(AF_INET,SOCK_STREAM,0);
    if(server_fd<0){ perror("socket"); exit(EXIT_FAILURE); }
    int opt=1; setsockopt(server_fd,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));

    address.sin_family=AF_INET;
    address.sin_addr.s_addr=INADDR_ANY;
    address.sin_port=htons(port);

    if(bind(server_fd,(struct sockaddr*)&address,sizeof(address))<0){ perror("bind"); exit(EXIT_FAILURE);}
    if(listen(server_fd,MAX_CLIENTS)<0){ perror("listen"); exit(EXIT_FAILURE);}

    init_clients();
    init_salons();
    printf("Serveur Chat V5 est en ecoute sur port %d\n",port);

    while(1){
        FD_ZERO(&readfds);
        FD_SET(server_fd,&readfds);
        max_fd=server_fd;
        for(int i=0;i<MAX_CLIENTS;i++) if(clients[i].socket>0){ FD_SET(clients[i].socket,&readfds); if(clients[i].socket>max_fd) max_fd=clients[i].socket;}
        if(select(max_fd+1,&readfds,NULL,NULL,NULL)<0){ perror("select"); continue; }

        if(FD_ISSET(server_fd,&readfds)){
            int new_socket=accept(server_fd,NULL,NULL);
            int added=0;
            for(int i=0;i<MAX_CLIENTS;i++){
                if(clients[i].socket==0){
                    clients[i].socket=new_socket; clients[i].is_registered=0; clients[i].nickname[0]='\0'; clients[i].salon[0]='\0';
                    send_to_client(i,"[Server] : Bienvenue ! Utilisez /nick <pseudo>");
                    added=1; break;
                }
            }
            if(!added){ char *msg="Server full\n"; send(new_socket,msg,strlen(msg),0); close(new_socket);}
        }

        for(int i=0;i<MAX_CLIENTS;i++){
            int sd=clients[i].socket;
            if(sd>0 && FD_ISSET(sd,&readfds)){
                memset(buffer,0,BUFFER_SIZE);
                int bytes=recv(sd,buffer,BUFFER_SIZE,0);
                if(bytes<=0){ remove_client_from_salon(i); close(sd); clients[i].socket=0; clients[i].is_registered=0; clients[i].nickname[0]='\0'; continue;}
                unsigned char dec[BUFFER_SIZE]={0}; aes_decrypt(buffer,dec,bytes); dec[BUFFER_SIZE-1]='\0';
                char *msg=(char*)dec;

                if(strcmp(msg,"/quit")==0){ send_to_client(i,"[Server] : You will be terminated"); remove_client_from_salon(i); close(sd); clients[i].socket=0; clients[i].is_registered=0; clients[i].nickname[0]='\0'; continue;}
                if(strncmp(msg,"/nick ",6)==0){ strncpy(clients[i].nickname,msg+6,MAX_NICK-1); clients[i].is_registered=1; send_to_client(i,"[Server] : Pseudo enregistré"); continue;}
                if(strncmp(msg,"/broadcast ",11)==0){ char text[BUFFER_SIZE]; snprintf(text,BUFFER_SIZE,"[%s]: %s",clients[i].nickname,msg+11); broadcast(i,text); continue;}
                if(strncmp(msg,"/msg ",5)==0){ char target[MAX_NICK],text[BUFFER_SIZE]; sscanf(msg+5,"%s %[^\n]",target,text); int found=0; for(int j=0;j<MAX_CLIENTS;j++){ if(clients[j].is_registered && strcmp(clients[j].nickname,target)==0){ char tmp[BUFFER_SIZE]; snprintf(tmp,BUFFER_SIZE,"[Private][%s]: %s",clients[i].nickname,text); send_to_client(j,tmp); found=1; break;}} if(!found) send_to_client(i,"[Server] : Utilisateur introuvable"); continue;}
                if(strncmp(msg,"/sendfile ",10)==0){ char target[MAX_NICK],filename[BUFFER_SIZE]; sscanf(msg+10,"%s %s",target,filename); int found=-1; for(int j=0;j<MAX_CLIENTS;j++) if(clients[j].is_registered && strcmp(clients[j].nickname,target)==0) {found=j; break;} if(found>=0) send_file(i,found,filename); else send_to_client(i,"[Server] : Utilisateur introuvable"); continue;}
                
                // Salon
                if(strncmp(msg,"/create ",8)==0){ char *salon=msg+8; if(find_salon(salon)>=0) send_to_client(i,"[Server] : Salon existe déjà"); else {add_client_to_salon(i,salon); send_to_client(i,"[Server] : Salon créé et rejoint");} continue;}
                if(strncmp(msg,"/join ",6)==0){ char *salon=msg+6; add_client_to_salon(i,salon); send_to_client(i,"[Server] : Salon rejoint"); continue;}
                if(strcmp(msg,"/leave")==0){ remove_client_from_salon(i); send_to_client(i,"[Server] : Vous avez quitté le salon"); continue;}
                if(strncmp(msg,"/salonmsg ",10)==0){ char text[BUFFER_SIZE]; snprintf(text,BUFFER_SIZE,"[%s][Salon]: %s",clients[i].nickname,msg+10); send_salon(i,text); continue;}

                send_to_client(i,msg);
            }
        }
    }

    close(server_fd);
    return 0;
}
