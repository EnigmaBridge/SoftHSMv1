//
// Created by Dusan Klinec on 22.06.15.
//

#ifndef SOFTHSMV1_SHSMAPIUTILS_H
#define SOFTHSMV1_SHSMAPIUTILS_H

#include <botan/types.h>
#include <string>
#include <json/json.h>
#include <botan/auto_rng.h>

// Boolean attribute for private keys, if set to true, the private key is stored in SHSM.
#define CKA_SHSM_KEY (CKA_VENDOR_DEFINED + 0x100)
// Integer attribute, stores private key handle for SHSM stored private key.
#define CKA_SHSM_KEY_HANDLE (CKA_VENDOR_DEFINED + 0x101)
// RSA private key type stored in SHSM.
#define CKO_PRIVATE_KEY_SHSM (CKO_VENDOR_DEFINED + CKO_PRIVATE_KEY)

// Type of the SHSM_KEY_HANDLE.
#define SHSM_KEY_HANDLE long
#define SHSM_INVALID_KEY_HANDLE -1l

class ShsmApiUtils {
private:
    static Botan::AutoSeeded_RNG prng;

public:
    /**
    * Creates new socket and connects to it using configured connection parameters.
    */
    static int connectSocket(const char * hostname, int port, uint64_t readTimeoutMilli = 0, uint64_t writeTimeoutMilli = 0);

    /**
     * Sets socket timeout.
     */
    static int setSocketTimeout(int socket, int timeoutType, uint64_t timeoutValueMilli = 0);

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
    static size_t hexToBytes(std::string input, Botan::byte * buff, size_t maxLen);

    /**
     * Returns integer representation of a digit.
     */
    static int hexdigitToInt(char ch);

    /**
     * Converts half-byte to a hex digit.
     */
    static char intToHexDigit(int c);

    /**
     * Generates random nonce into the given buffer of given length in bytes.
     */
    static bool generateNonceBytes(Botan::byte * buff, size_t len);

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
     * Converts given field to integer. It may be string-encoded integer or integer.
     */
    static int getIntFromJsonField(Json::Value &root, int * success);

    /**
     * Converts given field to unsigned integer. It may be string-encoded integer or integer.
     */
    static unsigned int getUIntFromJsonField(Json::Value &root, int * success);

    /**
     * Gets hexcoded uint 32 from the JSON field.
     */
    static unsigned int getHexUint32FromJsonField(Json::Value &root, int *success);

    /**
     * Extracts status value as an integer from the JSON response.
     */
    static unsigned int getStatus(Json::Value &root);

    /**
     * Computes size of the array needed to hold decoded hex-coded byte array.
     */
    static ssize_t getJsonByteArraySize(std::string &input);

    /**
     * Replaces "\\n" character with real new line. Used in certificate transport in PEM form.
     */
    static std::string fixNewLinesInResponse(std::string &input);

    /**
     * Removes " ", "\n", "\r", "\t".
     */
    static std::string removeWhiteSpace(std::string &input);

    /**
     * Reads 2 bytes representation, converts to unsigned long.
     * String has to be at least 4 characters long.
     */
    static unsigned long getInt16FromHexString(const char *buff);

    /**
     * Reads 4 bytes integer representation, converts to unsigned long.
     * String has to be at least 8 characters long.
     */
    static unsigned long getInt32FromHexString(const char *buff);

    /**
     * Writes long to the string on the given pointer. Has to have at least 4 B.
     */
    static void writeInt32ToHexString(unsigned long id, unsigned char *buff);

    /**
     * Reads 4 bytes long representation, converts to unsigned long.
     * Buff has to be at least 4 bytes long.
     */
    static unsigned long getInt32FromBuff(const char *buff);

    /**
     * Writes long to the string on the given pointer. Has to have at least 4 B.
     */
    static void writeInt32ToBuff(unsigned long id, unsigned char *buff);

    /**
     * Loads current time.
     */
    static void gettimespec(struct timespec *ts, uint32_t offset);

    /**
     * Computes a difference between tHigh and tLow and returns time in milliseconds.
     */
    static long diffTimeMilli(struct timeval * tLow, struct timeval * tHigh);
};


#endif //SOFTHSMV1_SHSMAPIUTILS_H
