#include <stdlib.h>
#include <stdio.h>
#include <regex.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

#define __USE_GNU
#define _POSIX_SOURCE 1 // POSIX compliant source
#define READ_SIZE 32


#define READ_FIZE_SIZE 1024

#define MAX_URL_SIZE 1024
#define regexFull "ftp://([a-zA-z0-9}]+):(.+)@([a-zA-z0-9|.|-]+):([0-9]+)/(.+)"
#define regexNoPort "ftp://([a-zA-z0-9}]+):(.+)@([a-zA-z0-9|.|-]+)/(.+)"
#define regexNoPass "ftp://([a-zA-z0-9}]+)@([a-zA-z0-9|.|-]+):([0-9]*)/(.+)"
#define regexOnlyPort "ftp://([a-zA-z0-9|.|-]+):([0-9]*)/(.+)"
#define regexOnlyUser "ftp://([a-zA-z0-9}]+)@([a-zA-z0-9|.|-]+)/(.+)"
#define regexSimple "ftp://([a-zA-z0-9|.|-]+)/(.+)"

#define passiveModeRegex "227 Entering Passive Mode \\(([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+),([0-9]+)\\)\\."

struct URL{
    char * protocol;
    char * user;
    char * password;
    char * host;
    char * path;
    int port;
};


regex_t passive_regex;

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

char * read_control_packet(int sockfd, int * size){
    char * buffer = NULL;
    int alloc_size = READ_SIZE;
    buffer = realloc(buffer, alloc_size);

    bool multiline = false;
    bool carriage = false;
    int chars_since_crlf = 0;


    while(true){
        char buf;
        // printf("read\n");
        int bytes = read(sockfd, &buf, 1);
        if(*size == alloc_size){
            buffer = realloc(buffer, alloc_size * 2);
            alloc_size *= 2;
        }
        buffer[*size] = buf;
        // printf("size: %d; chars_since_crlf: %i, char: 0x%x\n", *size, chars_since_crlf, buf);
        if(chars_since_crlf == 3 && buf == '-'){
            // printf("multiline mode\n");
            multiline = true;
        }
        if(chars_since_crlf == 3 && buf == ' '){
            // printf("no multiline mode\n");
            multiline = false;
        }
        if(buf == '\r'){
            carriage = true;
        }
        if(buf == '\n' && carriage){
            if(!multiline) break;
            chars_since_crlf = -1;
        }


        (*size)++, chars_since_crlf++;
    }
    

    return buffer;

}

int process_control_packet(char * packet, int size){
    if(size < 3){
        return -1;
    }
    int status = atoi(strndup(packet, 4));
    // printf("status: %d\n", status);
    if(status == 220){
        for(int i = 0; i < size; i++){
            printf("%c", packet[i]);
        }
        printf("\n");
    }
    return status;
}

bool is_data_present(int sockfd){
    int count = 0;
    ioctl(sockfd, FIONREAD, &count);
    return count != 0;
}


int login(int sockfd, struct URL url){
    char user[1024] = {0};
    char password[1024] = {0};
    sprintf(user, "USER %s\r\n", url.user);
    sprintf(password, "PASS %s\r\n", url.password);

    if(write(sockfd, user, strlen(user)) == -1){
        printf("Something went wrong while writting..\n");
        return 1;
    }

    int size = 0;
    char * packet = read_control_packet(sockfd, &size);
    int status = process_control_packet(packet, size);
    if(status != 331){
        printf("Expecting status 331 got %d: wrong username\n", status);
        free(packet);
        return 1;
    }
    free(packet);

    if(write(sockfd, password, strlen(password)) == -1){
        printf("Something went wrong while writting..\n");
        return 1;
    }

    size = 0;
    packet = read_control_packet(sockfd, &size);
    status = process_control_packet(packet, size);
    if(status != 230){
        printf("Expecting status 230 got %d:  wrong password\n", status);
        free(packet);
        return 1;
    }
    free(packet);
    

    return 0;
}


int get_passive(int sockfd){
    char * binary_mode = "TYPE I\r\n";
    char * passive = "PASV\r\n";

    if(write(sockfd, binary_mode, strlen(binary_mode)) == -1){
        printf("Something went wrong while writting..\n");
        return -1;
    }
    
    int size = 0;
    char * packet = read_control_packet(sockfd, &size);
    int status = process_control_packet(packet, size);
    if(status != 200){
        printf("Couldn't switch to binary mode\n");
        return -1;
    }
    free(packet);

    if(write(sockfd, passive, strlen(passive)) == -1){
        printf("Something went wrong while writting..\n");
        return -1;
    }
    size = 0;
    packet = read_control_packet(sockfd, &size);
    status = process_control_packet(packet, size);

    if(status != 227){
        printf("Couldn't get passive instead got status %d\n", status);
        return -1;
    }

    int maxGroups = 7;
    regmatch_t groupArray[7];

    if(regexec(&passive_regex, packet, maxGroups, groupArray, 0) != 0){
        printf("Couldn't match passive mode regex. Exiting.\n ");
    }

    char * ip1 = strndup(packet + groupArray[1].rm_so, groupArray[1].rm_eo - groupArray[1].rm_so);
    char * ip2 = strndup(packet + groupArray[2].rm_so, groupArray[2].rm_eo - groupArray[2].rm_so);
    char * ip3 = strndup(packet + groupArray[3].rm_so, groupArray[3].rm_eo - groupArray[3].rm_so);
    char * ip4 = strndup(packet + groupArray[4].rm_so, groupArray[4].rm_eo - groupArray[4].rm_so);

    int port1 = atoi(strndup(packet + groupArray[5].rm_so, groupArray[5].rm_eo - groupArray[5].rm_so));
    int port2 = atoi(strndup(packet + groupArray[6].rm_so, groupArray[6].rm_eo - groupArray[6].rm_so));

    int port = 256*port1 + port2;

    char ip[16] = {};
    sprintf(ip, "%s.%s.%s.%s", ip1, ip2, ip3, ip4);
    
    int passive_sockfd = socket(AF_INET, SOCK_STREAM, 0); 

    struct sockaddr_in sa;
    bzero(&sa, sizeof(struct sockaddr_in));
    inet_pton(AF_INET, ip, &(sa.sin_addr));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    if(connect(passive_sockfd, &sa, sizeof(struct sockaddr_in)) != 0){
        printf("Failed to connect to passive.\n");
        return -1;
    }
    printf("Passive connection established\n");

    return passive_sockfd;

}

long get_file_size(int sockfd, char * path){
    char sizeQuery[1024] = { 0 };
    sprintf(sizeQuery, "SIZE %s\r\n", path);

    if(write(sockfd, sizeQuery, strlen(sizeQuery)) == -1){
        printf("Something went wrong while writting..\n");
        return -1;
    }

    int size = 0;
    char * packet = read_control_packet(sockfd, &size);
    int status = process_control_packet(packet, size);

    if(status != 213){
        printf("Expected status 213 for file size got %d\n", status);
        return -1;
    }

    return atoi(strndup(packet+4, size-4));
}

int get_file(int sockfd, int passive_sockfd, char * path, int file_size){
    char retrQuery[1024] = { 0 };
    sprintf(retrQuery, "retr %s\r\n", path);

    if(write(sockfd, retrQuery, strlen(retrQuery)) == -1){
        printf("Something went wrong while writting..\n");
        return -1;
    }

    int size = 0;
    char * packet = read_control_packet(sockfd, &size);
    int status = process_control_packet(packet, size);

    if(status != 150){
        printf("Expected status 150 got %d\n", status);
        return -1;
    }
    char * filename = strrchr(path, '/');
    if(filename == NULL){
        filename = path;
    } else {
        filename++;
    }
    FILE * file = fopen(filename, "wb");
    if(file == NULL){
        printf("couldn't open file... exiting.");
        return;
    }

    int read_size = 0;
    int curr_partition = -1;
    int partitions = file_size/10;

    do{
        if((read_size/partitions) != curr_partition){
            printf("Progress: %.2f%%\n", ((float) read_size)/file_size * 100);
            curr_partition = read_size/partitions;
        }

        char bytes[READ_FIZE_SIZE] = {};
        if(read_size >= file_size) break;
        int bytes_read = read(passive_sockfd, &bytes, READ_FIZE_SIZE);
        if(bytes_read == -1){
            printf("An error occurred while downloading file... exiting.");
            return -1;
        }

        fwrite(bytes, 1, bytes_read, file);

        read_size += bytes_read;
    } while(read_size < file_size);

    fclose(file);
    printf("Progress: 100%%");
    
    size = 0;
    packet = read_control_packet(sockfd, &size);
    status = process_control_packet(packet, size);

    if(status != 226){
        printf("Expected file transfer okay got %d instead.\n", status);
        return -1;
    }

    return 0;

}

int main(int argc, char * argv[]){
    if(regcomp(&passive_regex, passiveModeRegex, REG_EXTENDED)){
        printf("Couldn't compile passive mode regex\n");
        return 1;
    }

    if(argc != 2){
        printf("Usage: download ftp://[<user>:<password>@]<host>/<url-path>\n");
        exit(1);
    }
    struct URL url;
    parse(&url, argv[1]);

    struct addrinfo * address = getAddressFromHostname(url.host);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0); 

    if(connect(sockfd, address->ai_addr, address->ai_addrlen) != 0){
        perror("failed to connect to server");
    } 
    sleep(1);
    if(is_data_present(sockfd)){
        int size;
        char * packet = read_control_packet(sockfd, &size);
        process_control_packet(packet, size);
    }
    if(login(sockfd, url) != 0){
        printf("Something went wrong while trying to login...\n");
        exit(1);
    }

    

    int passive_sockfd = get_passive(sockfd);
    if(passive_sockfd == -1){
        exit(1);
    }
    
    long file_size = get_file_size(sockfd, url.path);
    if(file_size == -1){
        exit(1);
    }

    printf("File size: %d\n", file_size);


    int file = get_file(sockfd, passive_sockfd, url.path, file_size);
    if(file == -1){
        exit(1);
    }

    char * quit = "QUIT\r\n";
    if(write(sockfd, quit, strlen(quit)) == -1){
        printf("Something went wrong while writting..\n");
        return -1;
    }

    int size = 0;
    char * packet = read_control_packet(sockfd, &size);
    int status = process_control_packet(packet, size);

    return 0;
}