#include <stdlib.h>
#include <stdio.h>
#include <regex.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

#define __USE_GNU
#define _POSIX_SOURCE 1 // POSIX compliant source
#define READ_SIZE 32

#define MAX_URL_SIZE 1024
#define regexFull "ftp://([a-zA-z0-9}]+):(.+)@([a-zA-z0-9|.|-]+):([0-9]+)/(.+)"
#define regexNoPort "ftp://([a-zA-z0-9}]+):(.+)@([a-zA-z0-9|.|-]+)/(.+)"
#define regexNoPass "ftp://([a-zA-z0-9}]+)@([a-zA-z0-9|.|-]+):([0-9]*)/(.+)"
#define regexOnlyPort "ftp://([a-zA-z0-9|.|-]+):([0-9]*)/(.+)"
#define regexOnlyUser "ftp://([a-zA-z0-9}]+)@([a-zA-z0-9|.|-]+)/(.+)"
#define regexSimple "ftp://([a-zA-z0-9|.|-]+)/(.+)"

struct URL{
    char * protocol;
    char * user;
    char * password;
    char * host;
    char * path;
    int port;
};


int parse(struct URL *url, char *str){
    size_t maxMatches = 7;
    regex_t regexCompiled;
    


    regmatch_t groupArray[maxMatches];

    if (regcomp(&regexCompiled, regexFull, REG_EXTENDED)){
        printf("Could not compile regular expression.\n");
        return 1;
    };

    if(regexec(&regexCompiled, str, maxMatches, groupArray, 0) == 0){
        printf("Match full!\n");
        url->user = strndup(str + groupArray[1].rm_so, groupArray[1].rm_eo - groupArray[1].rm_so);
        url->password = strndup(str + groupArray[2].rm_so, groupArray[2].rm_eo - groupArray[2].rm_so);
        url->host = strndup(str + groupArray[3].rm_so, groupArray[3].rm_eo - groupArray[3].rm_so);
        url->port = atoi(strndup(str + groupArray[4].rm_so, groupArray[4].rm_eo - groupArray[4].rm_so));
        url->path = strndup(str + groupArray[5].rm_so, groupArray[5].rm_eo - groupArray[5].rm_so);
        regfree(&regexCompiled);
        return 0;
    }
    regfree(&regexCompiled);

    if (regcomp(&regexCompiled, regexNoPort, REG_EXTENDED)){
        printf("Could not compile regular expression.\n");
        return 1;
    }
    if(regexec(&regexCompiled, str, maxMatches, groupArray, 0) == 0){
        printf("Match no port!\n");
        url->user = strndup(str + groupArray[1].rm_so, groupArray[1].rm_eo - groupArray[1].rm_so);
        url->password = strndup(str + groupArray[2].rm_so, groupArray[2].rm_eo - groupArray[2].rm_so);
        url->host = strndup(str + groupArray[3].rm_so, groupArray[3].rm_eo - groupArray[3].rm_so);
        url->port = 21;
        url->path = strndup(str + groupArray[4].rm_so, groupArray[4].rm_eo - groupArray[4].rm_so);
        regfree(&regexCompiled);
        return 0;
    }
    regfree(&regexCompiled);

    if (regcomp(&regexCompiled, regexNoPass, REG_EXTENDED)){
        printf("Could not compile regular expression.\n");
        return 1;
    }

    if(regexec(&regexCompiled, str, maxMatches, groupArray, 0) == 0){
        printf("Match no pass!\n");
        url->user = strndup(str + groupArray[1].rm_so, groupArray[1].rm_eo - groupArray[1].rm_so);
        url->password = getpass('Password: ');
        url->host = strndup(str + groupArray[2].rm_so, groupArray[2].rm_eo - groupArray[2].rm_so);
        url->port = atoi(strndup(str + groupArray[3].rm_so, groupArray[3].rm_eo - groupArray[3].rm_so));
        url->path = strndup(str + groupArray[4].rm_so, groupArray[4].rm_eo - groupArray[4].rm_so);
        regfree(&regexCompiled);
        return 0;
    }
    regfree(&regexCompiled);
    
    if (regcomp(&regexCompiled, regexOnlyPort, REG_EXTENDED)){
        printf("Could not compile regular expression.\n");
        return 1;
    }
    
    if (regexec(&regexCompiled, str, maxMatches, groupArray, 0) == 0){
        printf("Match only port!\n");
        url->user = "anonymous";
        url->password = "anonymous";
        url->host = strndup(str + groupArray[1].rm_so, groupArray[1].rm_eo - groupArray[1].rm_so);
        url->port = atoi(strndup(str + groupArray[2].rm_so, groupArray[2].rm_eo - groupArray[2].rm_so));
        url->path = strndup(str + groupArray[3].rm_so, groupArray[3].rm_eo - groupArray[3].rm_so);
        regfree(&regexCompiled);
        return 0;
    }
    regfree(&regexCompiled);

    if (regcomp(&regexCompiled, regexOnlyUser, REG_EXTENDED)){
        printf("Could not compile regular expression.\n");
        return 1;
    }

    if (regexec(&regexCompiled, str, maxMatches, groupArray, 0) == 0){
        printf("Match only user!\n");
        url->user = strndup(str + groupArray[1].rm_so, groupArray[1].rm_eo - groupArray[1].rm_so);
        char *password = getpass("Password: ");
        url->password = password;
        url->host = strndup(str + groupArray[2].rm_so, groupArray[2].rm_eo - groupArray[2].rm_so);
        url->port = 21;
        url->path = strndup(str + groupArray[3].rm_so, groupArray[3].rm_eo - groupArray[3].rm_so);
        regfree(&regexCompiled);
        return 0;
    }
    regfree(&regexCompiled);

    if(regcomp(&regexCompiled, regexSimple, REG_EXTENDED)){
        printf("Could not compile regular expression.\n");
        return 1;
    }

    if (regexec(&regexCompiled, str, maxMatches, groupArray, 0) == 0){
        printf("Match simple!\n");
        url->user = "anonymous";
        url->password = "anonymous@example.com";
        url->host = strndup(str + groupArray[1].rm_so, groupArray[1].rm_eo - groupArray[1].rm_so);
        url->port = 21;
        url->path = strndup(str + groupArray[2].rm_so, groupArray[2].rm_eo - groupArray[2].rm_so);
        regfree(&regexCompiled);
        return 0;
    }
    
    regfree(&regexCompiled);
    printf("No match!\n");
    exit(1);

}


struct addrinfo * getAddressFromHostname(char * hostname){
    struct addrinfo hints;
    memset(&hints, 0,sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM; // TCP stream sockets
    hints.ai_flags = 0;     // fill in my IP for me

    struct addrinfo * result;
    int error = getaddrinfo(hostname, "21", NULL, &result);


    if(error != 0){
        printf("Error: %d\n", error);
        perror("failed to get addr for hostname. Aborting download...");
        exit(1);
    }

    return result;

}

char remainder[READ_SIZE];
int bytesRemaining = 0;

char * read_control_packet(int sockfd, int * size){
    char * buffer = NULL;
    int alloc_size = READ_SIZE;
    buffer = realloc(buffer, alloc_size);
    if(bytesRemaining == 0){
        *size = 0;
    } else {
        memcpy(buffer, remainder, bytesRemaining);
        *size = bytesRemaining;
    }

    bool multiline = false;
    int chars_since_crlf = 0;

    while(true){
        char buf[READ_SIZE];
        int bytes = read(sockfd, buf, READ_SIZE);
        int i = 0;
        bool exit = false;
        for(; i < bytes; i++, (*size)++, chars_since_crlf++){
            printf("size: %d; i: %i, chars_since_crlf: %i, char: 0x%x\n", *size, i, chars_since_crlf, buf[i]);
            if((chars_since_crlf) == 3 && buf[i] == '-'){
                printf("multiline mode\n");
                multiline = true;
            }
            if((chars_since_crlf) == 3 && (buf[i] == ' ' || ((i + 1) < bytes && buf[i] == '\r' && buf[i+1] == '\n'))){
                printf("no multiline mode\n");
                multiline = false;
            }
            if((i + 1) < bytes && buf[i] == '\r' && buf[i+1] == '\n'){
                buffer[*size] = buf[i];
                (*size)++;
                buffer[*size] = buf[i+1];
                i++;
                if(*size == alloc_size){
                    buffer = realloc(buffer, alloc_size * 2);
                    alloc_size *= 2;
                }
                chars_since_crlf = -1;
                if(!multiline){
                    exit = true;
                    break;
                }
            }
            if(*size == alloc_size){
                buffer = realloc(buffer, alloc_size * 2);
                alloc_size *= 2;
            }
            buffer[*size] = buf[i];
        }
        if(exit && !multiline) {

            if(i != bytes){
                bytesRemaining = bytes - i;
                memcpy(remainder, buf+i, bytesRemaining);
            }
            break;
        }
    }
    

    return buffer;

}

int main(int argc, char * argv[]){
    if(argc != 2){
        printf("Usage: download ftp://[<user>:<password>@]<host>/<url-path>\n");
        exit(1);
    }
    struct URL testUrl;
    parse(&testUrl, argv[1]);
    printf("User: %s\n", testUrl.user);
    printf("Password: %s\n", testUrl.password);
    printf("Host: %s\n", testUrl.host);
    printf("Port: %d\n", testUrl.port);
    printf("Path: %s\n", testUrl.path);
    
    struct URL url;
    url.user = "anonymous";    
    url.password = "anonymous@example.com";
    url.host = "mirrors.up.pt";
    url.path = "crab.mp4";
    url.port = 21;


    struct addrinfo * address = getAddressFromHostname(url.host);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    char addr[16] = {0};
    inet_ntop(AF_INET, address->ai_addr->sa_data, addr, 16);

    printf("%s\n", addr);

    if(connect(sockfd, address->ai_addr, address->ai_addrlen) != 0){
        perror("failed to connect to server");
    }    

    int size;
    char * packet = read_control_packet(sockfd, &size);
    for(int i = 0; i < size; i++){
        printf("%c", packet[i]);
    }
    printf("\n");

    return 0;
}