//
// Created by Dusan Klinec on 22.06.15.
//

#ifndef SOFTHSMV1_SHSMAPIUTILS_H
#define SOFTHSMV1_SHSMAPIUTILS_H

#include <botan/types.h>
#include <string>
#include <json/json.h>

// Boolean attribute for private keys, if set to true, the private key is stored in SHSM.
#define CKA_SHSM_KEY (CKA_VENDOR_DEFINED + 0x100)
// Integer attribute, stores private key handle for SHSM stored private key.
#define CKA_SHSM_KEY_HANDLE (CKA_VENDOR_DEFINED + 0x101)
// RSA private key type stored in SHSM.
#define CKO_PRIVATE_KEY_SHSM (CKO_VENDOR_DEFINED + CKO_PRIVATE_KEY)

// Type of the SHSM_KEY_HANDLE.
#define SHSM_KEY_HANDLE long
#define SHSM_INVALID_KEY_HANDLE -1

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
    static std::string bytesToHex(const Botan::byte * byte, size_t len);

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

    /**
     * Generates JSON request for certificate generation.
     */
    static std::string getRequestForCertGen(long bitsize, const char *alg, const char *dn);

    /**
     * Returns request string for query for SHSM public key.
     */
    static std::string getRequestShsmPubKey(std::string nonce);

    /**
     * Extracts status value as an integer from the JSON response.
     */
    static int getStatus(Json::Value &root);

    /**
     * Computes size of the array needed to hold decoded hex-coded byte array.
     */
    static ssize_t getJsonByteArraySize(std::string &input);
};


#endif //SOFTHSMV1_SHSMAPIUTILS_H
