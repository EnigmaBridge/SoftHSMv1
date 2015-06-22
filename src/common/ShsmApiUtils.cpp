//
// Created by Dusan Klinec on 22.06.15.
//

#include <json.h>
#include <sstream>
#include <iomanip>
#include "ShsmApiUtils.h"

#include "log.h"
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <iomanip>
#include <string>
#include <iomanip>
#include <botan/types.h>

#define READ_STRING_BUFFER_SIZE 8192

int ShsmApiUtils::connectSocket(const char * hostname, int port) {
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        DEBUG_MSG("decryptCall", "ERROR in opening socket");
        return -1;
    }

    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;

    bcopy((char *)server->h_addr,
          (char *)&serv_addr.sin_addr.s_addr,
          (size_t)server->h_length);

    serv_addr.sin_port = htons(port);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){
        DEBUG_MSG("decryptCall", "ERROR connecting");
        return -2;
    }

    return sockfd;
}

int ShsmApiUtils::writeToSocket(int sockfd, std::string buffToWrite) {
    const char * cstr = buffToWrite.c_str();
    const size_t clen = (size_t) buffToWrite.length();
    if (clen == 0){
        return 0;
    }

    size_t writtenTotal=0;
    ssize_t written=0;
    while(writtenTotal != clen) {
        written = write(sockfd, cstr + writtenTotal, clen - writtenTotal);
        if (written < 0){
            DEBUG_MSG("writeToSocket", "ERROR in writing to a socket");
            return -1;
        }

        writtenTotal += written;
    }

    return 0;
}

std::string ShsmApiUtils::readStringFromSocket(int sockfd) {
    std::stringstream sb;
    char buffer[READ_STRING_BUFFER_SIZE];

    ssize_t bytesRead = 0;
    while((bytesRead = read(sockfd, buffer, READ_STRING_BUFFER_SIZE)) >= 0){
        sb.write(buffer, bytesRead);
    }

    return sb.str();
}

std::string ShsmApiUtils::request(const char *hostname, int port, std::string request, int *status) {

    // Connect to a remote SHSM socket.
    int sockfd = ShsmApiUtils::connectSocket(hostname, port);
    if (sockfd < 0){
        DEBUG_MSG("decryptCall", "Socket could not be opened");
        *status = -1;
        return "";
    }

    // Send request over the socket.
    int res = ShsmApiUtils::writeToSocket(sockfd, request);
    if (res < 0){
        DEBUG_MSG("decryptCall", "Socket could not be used for writing");
        *status = -2;
        return "";
    }

    // Read JSON response from HSMS.
    std::string response = ShsmApiUtils::readStringFromSocket(sockfd);

    // Closing opened socket. Refactor for performance.
    close(sockfd);

    *status = 0;
    return response;
}

std::string ShsmApiUtils::bytesToHex(const Botan::byte byte[], size_t len) {
    std::ostringstream ret;
    for (std::string::size_type i = 0; i < len; ++i) {
        ret << std::hex << std::setfill('0') << std::setw(2) << std::nouppercase << (int) byte[i];
    }

    return ret.str();
}

int ShsmApiUtils::hexToBytes(std::string input, Botan::byte * buff, size_t maxLen) {
    const size_t len = input.length();
    if (len & 1) {
        throw std::invalid_argument("odd length");
    }

    for(size_t i = 0; i < len && i < maxLen*2; i++) {
        const char a = input[i];
        int ahex = 0;
        if (a >= '0' && a <= '9') {
            ahex = (a - '0');
        } else if (a >= 'A' && a <= 'F') {
            ahex = (a - 'A' + 10);
        } else if (a >= 'a' && a <= 'f'){
            ahex = (a - 'a' + 10);
        } else {
            throw std::invalid_argument("illegal character");
        }

        if (i & 1){
            // Second half-byte, OR. First was already set.
            buff[i/2] |= ahex & 0xf;
        } else {
            // First half-byte, SET.
            buff[i/2]  = (unsigned char)(ahex & 0xf) << 4;
        }
    }

    return (int)(len / 2);
}

int ShsmApiUtils::hexdigitToInt(char ch) {
    switch (ch) {
        case '0':
            return 0;
        case '1':
            return 1;
        case '2':
            return 2;
        case '3':
            return 3;
        case '4':
            return 4;
        case '5':
            return 5;
        case '6':
            return 6;
        case '7':
            return 7;
        case '8':
            return 8;
        case '9':
            return 9;
        case 'a':
        case 'A':
            return 10;
        case 'b':
        case 'B':
            return 11;
        case 'c':
        case 'C':
            return 12;
        case 'd':
        case 'D':
            return 13;
        case 'e':
        case 'E':
            return 14;
        case 'f':
        case 'F':
            return 15;
        default:
            return -1;
    }
}

std::string ShsmApiUtils::generateNonce(size_t len) {
    static const char * alphabet = "0123456789abcdefghijklmnopqrstuvwxyz";

    std::stringstream res;
    for(int i = 0; i < len; i++){
        res << alphabet[rand() % (sizeof(alphabet) - 1)];
    }

    return res.str();
}
