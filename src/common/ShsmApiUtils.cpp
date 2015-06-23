//
// Created by Dusan Klinec on 22.06.15.
//

#include <iostream>     // std::cout
#include <json.h>
#include <sstream>
#include <iomanip>
#include "ShsmApiUtils.h"

#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdexcept>
#include <strings.h>
#include <iomanip>
#include <string>
#include <iomanip>
#include <botan/types.h>
#include <stdio.h>
#include <algorithm>

#define READ_STRING_BUFFER_SIZE 8192

int ShsmApiUtils::connectSocket(const char * hostname, int port) {
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        //ERROR_MSG("decryptCall", "ERROR in opening socket");
        return -1;
    }

    server = gethostbyname(hostname);
    if (server == NULL) {
        //ERROR_MSG("decryptCall", "ERROR, no such host");
        return -2;
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;

    bcopy((char *)server->h_addr,
          (char *)&serv_addr.sin_addr.s_addr,
          (size_t)server->h_length);

    serv_addr.sin_port = htons(port);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){
        //ERROR_MSG("decryptCall", "ERROR connecting");
        return -3;
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
            //DEBUG_MSG("writeToSocket", "ERROR in writing to a socket");
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
    while((bytesRead = read(sockfd, buffer, READ_STRING_BUFFER_SIZE)) > 0){
        sb.write(buffer, bytesRead);
    }

    return sb.str();
}

std::string ShsmApiUtils::request(const char *hostname, int port, std::string request, int *status) {

    // Connect to a remote SHSM socket.
    int sockfd = ShsmApiUtils::connectSocket(hostname, port);
    if (sockfd < 0){
        //DEBUG_MSG("decryptCall", "Socket could not be opened");
        *status = -1;
        return "";
    }

    // Send request over the socket.
    int res = ShsmApiUtils::writeToSocket(sockfd, request);
    if (res < 0){
        //DEBUG_MSG("decryptCall", "Socket could not be used for writing");
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

std::string ShsmApiUtils::bytesToHex(const Botan::byte * byte, size_t len) {
    std::ostringstream ret;
    for (std::string::size_type i = 0; i < len; ++i) {
        ret << std::hex << std::setfill('0') << std::setw(2) << std::nouppercase << (int) byte[i];
    }

    return ret.str();
}

int ShsmApiUtils::hexToBytes(std::string input, Botan::byte * buff, size_t maxLen) {
    const size_t len = input.length();
    size_t curByte = 0;
    for(size_t i = 0; i < len && curByte < maxLen*2; i++) {
        const char a = input[i];
        int ahex = 0;
        if (a >= '0' && a <= '9') {
            ahex = (a - '0');
        } else if (a >= 'A' && a <= 'F') {
            ahex = (a - 'A' + 0xa);
        } else if (a >= 'a' && a <= 'f') {
            ahex = (a - 'a' + 0xa);
        } else if (a == ' ' || a == '\n' || a == '\t'){
            continue;
        } else {
            throw std::invalid_argument("illegal character");
        }

        if (curByte & 1){
            // Second half-byte, OR. First was already set.
            buff[curByte/2] |= (unsigned char)(ahex & 0xf);
        } else {
            // First half-byte, SET.
            buff[curByte/2]  = (unsigned char)(ahex & 0xf) << 4;
        }

        curByte += 1;
    }

    return (int)(curByte/2);
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
    static const size_t alphabetLen = strlen(alphabet);

    std::stringstream res;
    for(size_t i = 0; i < len; i++){
        res << alphabet[rand() % (alphabetLen - 1)];
    }

    return res.str();
}

std::string ShsmApiUtils::getRequestForCertGen(long bitsize, const char *alg, const char *dn) {
    // Generate JSON request here.
    Json::Value jReq;
    jReq["function"] = "CreateUserObject";
    jReq["version"] = "1.0";
    jReq["nonce"] = ShsmApiUtils::generateNonce(16);
    jReq["type"] = 6;

    Json::Value jData;
    jData["dn"] = dn;
    jData["size"] = (int) bitsize;
    jData["algorithm"] = alg;

    // Add data for cert gen.
    jReq["data"] = jData;

    // Build string request body.
    Json::FastWriter jWriter;
    std::string json = jWriter.write(jReq) + "\n"; // EOL at the end of the request.
    return json;
}

std::string ShsmApiUtils::getRequestShsmPubKey(std::string nonce) {
    // Generate JSON request here.
    Json::Value jReq;
    jReq["function"] = "GetSHSMPubKey";
    jReq["version"] = "1.0";
    jReq["nonce"] = nonce;

    // Build string request body.
    Json::FastWriter jWriter;
    std::string json = jWriter.write(jReq) + "\n"; // EOL at the end of the request.
    return json;
}

int ShsmApiUtils::getStatus(Json::Value &root) {
    Json::Value status = root["status"];
    if (status.isNull()){
        return -1;
    }

    if (status.isIntegral()){
        return status.asInt();
    }

    if (status.isString()){
        return atoi(status.asCString());
    }

    return -2;
}

ssize_t ShsmApiUtils::getJsonByteArraySize(std::string &input) {
    const size_t len = input.length();
    ssize_t totalLen = 0;

    for (size_t i = 0; i < len; i++){
        const char c = input[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')){
            totalLen += 1;
        }
    }

    return totalLen / 2;
}

std::string ShsmApiUtils::fixNewLinesInResponse(std::string &input) {
    std::string copy = input;

    const std::string s1 = "\\\\n";
    const std::string t1 = "\n";

    const std::string s2 = "\\n";
    const std::string t2 = "\n";

    // s1 -> t1
    std::string::size_type n = 0;
    while ( ( n = copy.find( s1, n ) ) != std::string::npos ) {
        copy.replace( n, s1.size(), t1 );
        n += t1.size();
    }

    // s2 -> t2
    n=0;
    while ( ( n = copy.find( s1, n ) ) != std::string::npos ) {
        copy.replace( n, s1.size(), t1 );
        n += t1.size();
    }

    return copy;
}

std::string ShsmApiUtils::removeWhiteSpace(std::string &input) {
    std::string copy = input;
    copy.erase(std::remove_if(copy.begin(), copy.end(), ::isspace), copy.end());
    return copy;
}
