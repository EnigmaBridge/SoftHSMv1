//
// Created by Dusan Klinec on 21.06.15.
//

#include "ShsmUtils.h"
#include "log.h"
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <iomanip>
#include <string>
#include <iomanip>
#include <botan/types.h>
#include <sstream>
#include <json.h>

#define READ_STRING_BUFFER_SIZE 8192

int ShsmUtils::connectSocket(ShsmConnectionConfig * connectionConfig) {
    int sockfd;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        DEBUG_MSG("decryptCall", "ERROR in opening socket");
        return -1;
    }

    server = gethostbyname(connectionConfig->getMHost().c_str());
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;

    bcopy((char *)server->h_addr,
          (char *)&serv_addr.sin_addr.s_addr,
          (size_t)server->h_length);

    serv_addr.sin_port = htons(connectionConfig->getMPort());
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){
        DEBUG_MSG("decryptCall", "ERROR connecting");
        return -2;
    }

    return sockfd;
}

int ShsmUtils::writeToSocket(int sockfd, std::string buffToWrite) {
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

std::string ShsmUtils::readStringFromSocket(int sockfd) {
    std::stringstream sb;
    char buffer[READ_STRING_BUFFER_SIZE];

    ssize_t bytesRead = 0;
    while((bytesRead = read(sockfd, buffer, READ_STRING_BUFFER_SIZE)) >= 0){
        sb.write(buffer, bytesRead);
    }

    return sb.str();
}

std::string ShsmUtils::bytesToHex(const Botan::byte byte[], size_t len) {
    std::ostringstream ret;
    for (std::string::size_type i = 0; i < len; ++i) {
        ret << std::hex << std::setfill('0') << std::setw(2) << std::nouppercase << (int) byte[i];
    }

    return ret.str();
}

int ShsmUtils::hexToBytes(std::string input, char *buff, size_t maxLen) {
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
            buff[i/2]  = (char)(ahex & 0xf) << 4;
        }
    }

    return (int)(len / 2);
}

CK_BBOOL ShsmUtils::isShsmKey(SoftDatabase *db, CK_OBJECT_HANDLE hKey) {
    return db->getBooleanAttribute(hKey, CKA_SHSM_KEY, CK_FALSE);
}

SHSM_KEY_HANDLE ShsmUtils::getShsmKeyHandle(SoftDatabase *db, CK_OBJECT_HANDLE hKey) {
    SHSM_KEY_HANDLE shsmHandle;

    // Load this attribute via generic DB access call.
    const CK_ATTRIBUTE attr = {CKA_SHSM_KEY_HANDLE, (void *) &shsmHandle, sizeof(SHSM_KEY_HANDLE)};
    CK_RV shsmRet = db->getAttribute(hKey, &attr);

    if (shsmRet != CKR_OK){
        return SHSM_INVALID_KEY_HANDLE;
    }

    return shsmHandle;
}

std::string ShsmUtils::getRequestShsmPubKey(std::string nonce) {
    // Generate JSON request here.
    Json::Value jReq;
    jReq["function"] = "GetSHSMPubKey";
    jReq["version"] = "1.0";
    jReq["nonce"] = nonce;


    // Build string request body.
    Json::Writer jWriter;
    std::string json = jWriter.write(jReq) + "\n"; // EOL at the end of the request.
    return json;
}

std::string ShsmUtils::getRequestDecrypt(ShsmPrivateKey *privKey, const Botan::byte byte[], size_t t, std::string nonce) {
    // Generate JSON request here.
    Json::Value jReq;
    jReq["function"] = "ProcessData";
    jReq["version"] = "1.0";
    jReq["nonce"] = nonce;
    jReq["objectid"] = privKey->getKeyId();
    const std::string dataPrefix = "Packet0_RSA2048_";
    const std::stringstream dataBuilder;
    dataBuilder << dataPrefix;

    // Add hex-encoded input data here.
    dataBuilder << ShsmUtils::bytesToHex(byte, t);

    // Build string request body.
    Json::Writer jWriter;
    std::string json = jWriter.write(jReq) + "\n"; // EOL at the end of the request.
    return json;
}



