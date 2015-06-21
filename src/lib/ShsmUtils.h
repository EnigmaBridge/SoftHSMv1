//
// Created by Dusan Klinec on 21.06.15.
//

#ifndef SOFTHSMV1_SHSMUTILS_H
#define SOFTHSMV1_SHSMUTILS_H


#include "ShsmConnectionConfig.h"
#include "PK_HSMPrivateKey.h"
#include <string>

class ShsmUtils {
public:
    /**
     * Creates new socket and connects to it using configured connection parameters.
     */
    static int connectSocket(ShsmConnectionConfig * connectionConfig);

    /**
     * Writes the whole string to the socket.
     */
    static int writeToSocket(int sockfd, std::string buffToWrite);

    /**
     * Read string from the socket until there is some data.
     */
    static std::string readStringFromSocket(int sockfd);

    /**
     * Converts byte array to hexencoded string.
     */
    static std::string bytesToHex(const Botan::byte byte[], size_t len);

    /**
     * Converts hex encoded byte buffer in string to byte buffer.
     */
    static int hexToBytes(std::string input, char * buff, size_t maxLen);

    /**
     * Returns request string for query for SHSM public key.
     */
    static std::string getRequestShsmPubKey(std::string nonce);

    /**
     * Returns request string for decryption query.
     */
    static std::string getRequestDecrypt(PK_HSMPrivateKey * privKey, const Botan::byte byte[], size_t t, std::string nonce);

};


#endif //SOFTHSMV1_SHSMUTILS_H
