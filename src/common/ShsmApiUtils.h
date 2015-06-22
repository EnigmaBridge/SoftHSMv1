//
// Created by Dusan Klinec on 22.06.15.
//

#ifndef SOFTHSMV1_SHSMAPIUTILS_H
#define SOFTHSMV1_SHSMAPIUTILS_H


#include "ShsmConnectionConfig.h"

class ShsmApiUtils {

public:
    /**
    * Creates new socket and connects to it using configured connection parameters.
    */
    static int connectSocket(const char * hostname, int port);

    /**
     * Writes the whole string to the socket.
     */
    static int writeToSocket(int sockfd, std::string buffToWrite);

    /**
     * Read string from the socket until there is some data.
     */
    static std::string readStringFromSocket(int sockfd);

    /**
     * Performs one request on a newly created socket.
     * Wrapper call for connect, write request, read response.
     */
    static std::string request(const char * hostname, int port, std::string request, int * status);

    /**
     * Converts byte array to hexencoded string.
     */
    static std::string bytesToHex(const Botan::byte byte[], size_t len);

    /**
     * Converts hex encoded byte buffer in string to byte buffer.
     */
    static int hexToBytes(std::string input, Botan::byte * buff, size_t maxLen);

    /**
     * Returns integer representation of a digit.
     */
    static int hexdigitToInt(char ch);

    /**
     * Generates random nonce string.
     */
    static std::string generateNonce(size_t len);
};


#endif //SOFTHSMV1_SHSMAPIUTILS_H
