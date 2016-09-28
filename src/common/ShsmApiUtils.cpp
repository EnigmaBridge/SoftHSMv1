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
#include <cstdarg>

// TODO: if win32, do differently.
#include <sys/time.h>

// Logging
#ifndef WIN32
#  include <syslog.h>
#  include <stdarg.h>
#  include <stdio.h>
#else
#  include <windows.h>
#  include <stdio.h>
#endif

const char * EB_REQUEST_TYPES[] = {
    "PLAINAES",
    "PLAINAESDECRYPT",
    "RSA1024",
    "RSA2048",
    "AUTH_HOTP",
    "AUTH_PASSWD",
    "AUTH_NEWUSERCTX",
    "AUTH_UPDATEUSERCTX",
    "RANDOMDATA",
    "CREATENEWUO",
    "EC_FP192SIGN",
    "TOKENIZE",
    "DETOKENIZE",
    "TOKENIZEWRAP"
};

// PRNG, auto seeded, static.
Botan::AutoSeeded_RNG ShsmApiUtils::prng;

// Debugging logging
#ifdef EB_DEBUG_TO_STDERR
   static void debugLogStderr(const char * fmt, ...);
#  define DEBUG_LOG(arg) logDebugSyslogF arg
#else
   static void logDebugSyslogF(const char *text, ...);
#  define DEBUG_LOG(arg) logDebugSyslogF arg
#endif

#define READ_STRING_BUFFER_SIZE 4096

int ShsmApiUtils::setSocketTimeout(int socket, int timeoutType, uint64_t timeoutValueMilli) {
    if (timeoutValueMilli == 0){
        return 0;
    }

    if (timeoutType != SO_SNDTIMEO && timeoutType != SO_RCVTIMEO){
        return -100;
    }

    struct timeval timeout;
    timeout.tv_sec = (long) (timeoutValueMilli / 1000);
    timeout.tv_usec = 0;

    int sockOptRes = setsockopt (socket, SOL_SOCKET, timeoutType, (char *)&timeout, sizeof(timeout));
    return sockOptRes;
}

int ShsmApiUtils::connectSocket(const char * hostname, int port, uint64_t readTimeoutMilli, uint64_t writeTimeoutMilli) {
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    DEBUG_LOG(("Resolving server name: %s\n", hostname));
    server = gethostbyname(hostname);
    if (server == NULL) {
        return -2;
    }

    DEBUG_LOG(("Server name resolved\n"));
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;

    bcopy((char *)server->h_addr,
          (char *)&serv_addr.sin_addr.s_addr,
          (size_t)server->h_length);

    serv_addr.sin_port = htons(port);

    // Timeout set to the socket?
    if (ShsmApiUtils::setSocketTimeout(sockfd, SO_RCVTIMEO, readTimeoutMilli) < 0){
        DEBUG_LOG(("Cannot set socket read timeout...\n"));
        return -40;
    }

    if (ShsmApiUtils::setSocketTimeout(sockfd, SO_SNDTIMEO, writeTimeoutMilli) < 0){
        DEBUG_LOG(("Cannot set socket write timeout...\n"));
        return -41;
    }

    DEBUG_LOG(("Socket connecting...\n"));
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){
        return -3;
    }

    DEBUG_LOG(("Socket connected\n"));
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
        DEBUG_LOG(("Socket written: %d\n", (int) written));
        if (written < 0){
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
    struct timeval tm1;
    struct timeval tm2;
    gettimeofday(&tm1, NULL);
    DEBUG_LOG(("Going to create a socket to %s:%d\n", hostname, port));

    // Connect to a remote SHSM socket.
    int sockfd = ShsmApiUtils::connectSocket(hostname, port, 90000ul, 90000ul);
    if (sockfd < 0){
        DEBUG_LOG(("Socket could not be opened\n"));
        //DEBUG_MSG("decryptCall", "Socket could not be opened");
        if (status) *status = sockfd;
        return "";
    }

    DEBUG_LOG(("Socket opened: %d\n", sockfd));
    // Send request over the socket.
    int res = ShsmApiUtils::writeToSocket(sockfd, request);
    if (res < 0){
        //DEBUG_MSG("decryptCall", "Socket could not be used for writing");
        if (status) *status = -20;
        return "";
    }

    DEBUG_LOG(("Socket data written, length: %lu\n", request.length()));

    // Read JSON response from HSMS.
    std::string response = ShsmApiUtils::readStringFromSocket(sockfd);
    // Closing opened socket. Refactor for performance.
    close(sockfd);

    gettimeofday(&tm2, NULL);
    DEBUG_LOG(("Socket data read, length: %lu\n", response.length()));
    DEBUG_LOG(("Time spent in the request call: %ld ms\n", ShsmApiUtils::diffTimeMilli(&tm1, &tm2)));

    if (status) *status = 0;
    return response;
}

std::string ShsmApiUtils::bytesToHex(const Botan::byte * byte, size_t len) {
    std::ostringstream ret;
    for (std::string::size_type i = 0; i < len; ++i) {
        ret << std::hex << std::setfill('0') << std::setw(2) << std::nouppercase << (int) byte[i];
    }

    return ret.str();
}

size_t ShsmApiUtils::hexToBytes(std::string input, Botan::byte * buff, size_t maxLen) {
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

    return (curByte/2);
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

char ShsmApiUtils::intToHexDigit(int c) {
    if (c < 0 || c > 0xf){
        return 0x0;
    }

    return (char)((c <= 9) ? ('0' + c) : ('a' + (c - 10)));
}

bool ShsmApiUtils::generateNonceBytes(Botan::byte * buff, size_t len) {
    ShsmApiUtils::prng.randomize(buff, len);
    return true;
}

std::string ShsmApiUtils::generateNonce(size_t len) {
    static const char * alphabet = "0123456789abcdef";
    static const size_t alphabetLen = strlen(alphabet);

    std::stringstream res;
    for(size_t i = 0; i < len; i++){
        res << alphabet[ShsmApiUtils::prng.next_byte() % (alphabetLen - 1)];
    }

    return res.str();
}

std::string ShsmApiUtils::generateApiObjectId(const std::string apiKey, SHSM_KEY_HANDLE uoId, SHSM_KEY_TYPE uoType){
    std::stringstream res;
    res << apiKey;
    res << std::hex << std::fixed << std::setfill('0') << std::setw(10) << ((unsigned)uoId);
    res << std::hex << std::fixed << std::setfill('0') << std::setw(10) << ((unsigned)uoType);
    return res.str();
}

std::string ShsmApiUtils::getRequestForCertGen(std::string apiKey, long bitsize, const char *alg, const char *dn) {
    // Generate JSON request here.
    Json::Value jReq;
    jReq["function"] = "CreateUserObject";
    jReq["version"] = "1.0";
    jReq["nonce"] = ShsmApiUtils::generateNonce(16);
    jReq["type"] = "6";
    jReq["objectid"] = ShsmApiUtils::generateApiObjectId(apiKey, 0);

    Json::Value jData;
    jData["dn"] = dn;
    // Size and algorithm not supported by now. Specified by "type". TODO: fix.
    //jData["size"] = (int) bitsize;
    //jData["algorithm"] = alg;

    // Add data for cert gen.
    jReq["data"] = jData;

    // Build string request body.
    Json::FastWriter jWriter;
    std::string json = jWriter.write(jReq) + "\n"; // EOL at the end of the request.
    return json;
}

std::string ShsmApiUtils::getRequestShsmPubKey(std::string apiKey, std::string nonce) {
    // Generate JSON request here.
    Json::Value jReq;
    jReq["function"] = "GetImportPublicKey";
    jReq["version"] = "1.0";
    jReq["nonce"] = nonce;
    jReq["objectid"] = ShsmApiUtils::generateApiObjectId(apiKey, 0);

    // Build string request body.
    Json::FastWriter jWriter;
    std::string json = jWriter.write(jReq) + "\n"; // EOL at the end of the request.
    return json;
}

int ShsmApiUtils::getIntFromJsonField(Json::Value &root, int * success) {
    if (root.isNull()){
        if (success != NULL){
            *success = -1;
        }
        return -1;
    }

    if (success != NULL){
        *success = 0;
    }

    if (root.isIntegral()){
        return root.asInt();
    }

    if (root.isString()){
        return atoi(root.asCString());
    }

    if (success != NULL){
        *success = -2;
    }

    return -2;
}

unsigned int ShsmApiUtils::getUIntFromJsonField(const Json::Value &root, int * success) {
    if (root.isNull()){
        if (success != NULL){
            *success = -1;
        }
        return 0;
    }

    if (success != NULL){
        *success = 0;
    }

    if (root.isIntegral()){
        return root.asUInt();
    }

    if (root.isString()){
        return (unsigned)atoi(root.asCString());
    }

    if (success != NULL){
        *success = -2;
    }

    return 0;
}

unsigned int ShsmApiUtils::getHexUint32FromJsonField(const Json::Value &root, int *success) {
    if (root.isNull()){
        if (success != NULL){
            *success = -1;
        }
        return 0;
    }

    if (success != NULL){
        *success = 0;
    }

    if (root.isIntegral()){
        return root.asUInt();
    }

    if (root.isString()){
        const unsigned long ln = root.asString().length();
        if (ln == 8) {
            return (unsigned int) ShsmApiUtils::getInt32FromHexString(root.asCString());
        } else if (ln == 4){
            return (unsigned int) ShsmApiUtils::getInt16FromHexString(root.asCString());
        } else if (ln<8) {
            const char * orig = root.asCString();
            char buff[] = "00000000";
            for(unsigned i = 0; i<ln; i++){
                buff[8-ln+i] = orig[i];
            }
            return (unsigned int) ShsmApiUtils::getInt32FromHexString(buff);
        }
    }

    if (success != NULL){
        *success = -2;
    }

    return 0;
}

unsigned int ShsmApiUtils::getStatus(Json::Value &root) {
    Json::Value status = root["status"];
    return ShsmApiUtils::getHexUint32FromJsonField(status, NULL);
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
    while ( ( n = copy.find( s2, n ) ) != std::string::npos ) {
        copy.replace( n, s2.size(), t2 );
        n += t2.size();
    }

    return copy;
}

std::string ShsmApiUtils::removeWhiteSpace(std::string &input) {
    std::string copy = input;
    copy.erase(std::remove_if(copy.begin(), copy.end(), ::isspace), copy.end());
    return copy;
}

unsigned long ShsmApiUtils::getInt16FromBuff(const Botan::byte * buff) {
    unsigned long data = (((unsigned long)buff[1]) & 0xff);
    data |= (((unsigned long)buff[0]) & 0xff) << 8;
    return data;
}

unsigned long ShsmApiUtils::getInt16FromHexString(const char *buff) {
    unsigned long data = (unsigned long) ShsmApiUtils::hexdigitToInt(buff[3]);
    data |= ((unsigned long) ShsmApiUtils::hexdigitToInt(buff[2])) << 4;
    data |= ((unsigned long) ShsmApiUtils::hexdigitToInt(buff[1])) << 8;
    data |= ((unsigned long) ShsmApiUtils::hexdigitToInt(buff[0])) << 12;
    return data;
}

unsigned long ShsmApiUtils::getInt32FromHexString(const char *buff) {
    unsigned long data = (unsigned long) ShsmApiUtils::hexdigitToInt(buff[7]);
    data |= ((unsigned long) ShsmApiUtils::hexdigitToInt(buff[6])) << 4;
    data |= ((unsigned long) ShsmApiUtils::hexdigitToInt(buff[5])) << 8;
    data |= ((unsigned long) ShsmApiUtils::hexdigitToInt(buff[4])) << 12;
    data |= ((unsigned long) ShsmApiUtils::hexdigitToInt(buff[3])) << 16;
    data |= ((unsigned long) ShsmApiUtils::hexdigitToInt(buff[2])) << 20;
    data |= ((unsigned long) ShsmApiUtils::hexdigitToInt(buff[1])) << 24;
    data |= ((unsigned long) ShsmApiUtils::hexdigitToInt(buff[0])) << 28;
    return data;
}

void ShsmApiUtils::writeInt32ToHexString(unsigned long id, unsigned char *buff) {
    buff[0] = 0;
    buff[1] = 0;
    buff[2] = 0;
    buff[3] = 0;

    buff[3] |= (unsigned char) ShsmApiUtils::intToHexDigit( (int) (id & 0xf) );
    buff[3] |= (unsigned char) ShsmApiUtils::intToHexDigit( (int) ((id >> 4 ) & 0xf));
    buff[2] |= (unsigned char) ShsmApiUtils::intToHexDigit( (int) ((id >> 8 ) & 0xf) );
    buff[2] |= (unsigned char) ShsmApiUtils::intToHexDigit( (int) ((id >> 12) & 0xf) );
    buff[1] |= (unsigned char) ShsmApiUtils::intToHexDigit( (int) ((id >> 16) & 0xf) );
    buff[1] |= (unsigned char) ShsmApiUtils::intToHexDigit( (int) ((id >> 20) & 0xf) );
    buff[0] |= (unsigned char) ShsmApiUtils::intToHexDigit( (int) ((id >> 24) & 0xf) );
    buff[0] |= (unsigned char) ShsmApiUtils::intToHexDigit( (int) ((id >> 28) & 0xf) );
}

unsigned long ShsmApiUtils::getInt32FromBuff(const char *buff) {
    unsigned long data = (unsigned long) ((unsigned char) buff[3]) & 0xff;
    data |= ((unsigned long) ((unsigned char) buff[2]) & 0xff) << 8;
    data |= ((unsigned long) ((unsigned char) buff[1]) & 0xff) << 16;
    data |= ((unsigned long) ((unsigned char) buff[0]) & 0xff) << 24;
    return data;
}

void ShsmApiUtils::writeInt32ToBuff(unsigned long id, unsigned char *buff) {
    buff[3] = (unsigned char) (id & 0xff);
    buff[2] = (unsigned char) ((id >> 8 ) & 0xff);
    buff[1] = (unsigned char) ((id >> 16) & 0xff);
    buff[0] = (unsigned char) ((id >> 24) & 0xff);
}

void ShsmApiUtils::writeInt16ToBuff(int id, unsigned char *buff) {
    buff[1] = (unsigned char) (id & 0xff);
    buff[0] = (unsigned char) ((id >> 8 ) & 0xff);
}

void ShsmApiUtils::gettimespec(struct timespec *ts, uint32_t offset) {
    struct timeval tv;
    (void)gettimeofday(&tv, NULL);
    ts->tv_sec  = tv.tv_sec + offset;
    ts->tv_nsec = tv.tv_usec * 1000;
}

long ShsmApiUtils::diffTimeMilli(struct timeval *tLow, struct timeval *tHigh) {
    return 1000l * (tHigh->tv_sec - tLow->tv_sec) + (tHigh->tv_usec - tLow->tv_usec) / 1000l;
}

int ShsmApiUtils::randomInt() {
    int toReturn = 0;
    prng.randomize((Botan::byte *) &toReturn, sizeof(int));
    return toReturn;
}

std::string ShsmApiUtils::json2string(const Json::Value &json) {
    // Build string request body.
    Json::FastWriter jWriter;
    return jWriter.write(json);
}

std::string ShsmApiUtils::getRequestBody(const Json::Value &jsonRequest) {
    // Build string request body.
    Json::FastWriter jWriter;
    std::string json = jWriter.write(jsonRequest) + "\n"; // EOL at the end of the request.
    return json;
}

#ifdef EB_DEBUG_TO_STDERR

static void debugLogStderr(const char * fmt, ...){
    char msgBuff[2048];
    snprintf(msgBuff, 2048, "SoftHSM: %s", fmt);

    va_list arg;
    va_start(arg, fmt);
    vfprintf(stderr, msgBuff, arg);
    va_end(arg);
}
#else

static void logDebugSyslogF(const char *text, ...) {
#ifndef WIN32
    char msgBuff[4096];
    snprintf(msgBuff, 4096, "SoftHSM: %s", text);

    va_list arg;
    va_start(arg, text);
    vsyslog(LOG_DEBUG, msgBuff, arg);
    va_end(arg);
#else
#warning not implemented
#endif
}

#endif
