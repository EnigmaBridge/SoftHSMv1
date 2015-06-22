//
// Created by Dusan Klinec on 18.06.15.
//

#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <iomanip>
#include "PK_Decryptor_EME_Remote.h"
#include "ShsmUtils.h"
#include "ShsmApiUtils.h"


PK_Decryptor_EME_Remote::PK_Decryptor_EME_Remote(const ShsmPrivateKey * key,
                                                 const std::string &eme,
                                                 const SoftSlot *curSlot) : PK_Decryptor_EME(*key, eme)
{
    std::string host = curSlot->getHost();
    std::string ckey = curSlot->getKey();
    int port = curSlot->getPort();

    if (host.empty()){
        return;
    }

    this->eme = eme;
    this->privKey = key;
    this->connectionConfig = new ShsmConnectionConfig(host, port);
    this->connectionConfig->setKey(ckey);
}

Botan::SecureVector<Botan::byte> PK_Decryptor_EME_Remote::decryptCall(const Botan::byte byte[], size_t t, int * status) const {
    // Generate JSON request for decryption.
    Botan::SecureVector errRet = Botan::SecureVector<Botan::byte>(0);
    std::string json = ShsmUtils::getRequestDecrypt(this->privKey, this->connectionConfig->getKey(), byte, t, "");

    // Perform the request.
    int reqResult = 0;
    std::string response = ShsmApiUtils::request(this->connectionConfig->getMHost().c_str(),
                                                 this->connectionConfig->getMPort(),
                                                 json, &reqResult);
    if (!reqResult){
        return errRet;
    }

    // Parse response, extract result, return it.
    Json::Value root;   // 'root' will contain the root value after parsing.
    Json::Reader reader;
    bool parsedSuccess = reader.parse(response, root, false);
    if(!parsedSuccess) {
        DEBUG_MSG("decryptCall", "Could not read data from socket");
        return errRet;
    }

    // Check status code.
    if (root["status"].asInt() != 9000){
        DEBUG_MSG("decryptCall", "Result code is not 9000, cannot decrypt");
        return errRet;
    }

    // Process result.
    std::string resultString = root["result"].asString();
    if (resultString.empty() || resultString.length() < 4){
        DEBUG_MSG("decryptCall", "Response string is too short.");
        return errRet;
    }

    // Read prefix, first 4 bytes. unsigned long?
    unsigned long prefix = (unsigned long) ShsmApiUtils::hexdigitToInt(resultString[3]);
    prefix |= ((unsigned long) ShsmApiUtils::hexdigitToInt(resultString[2])) << 8;
    prefix |= ((unsigned long) ShsmApiUtils::hexdigitToInt(resultString[1])) << 16;
    prefix |= ((unsigned long) ShsmApiUtils::hexdigitToInt(resultString[0])) << 24;

    // Strip suffix of the key beginning with "Packet"
    size_t pos = resultString.rfind("Packet", std::string::npos);
    std::string decrytpedHexCoded = resultString.substr(4 + prefix,
                                                        pos == std::string::npos ? resultString.length() - 4 : pos - 4 - prefix);

    // Allocate memory buffer for decrypted block, convert from hexa string coding to bytes
    const size_t decHexLen = decrytpedHexCoded.length();

    ssize_t bufferLen = decHexLen / 2;
    Botan::byte * buff = (Botan::byte *) malloc(sizeof(Botan::byte) * bufferLen);
    ShsmApiUtils::hexToBytes(decrytpedHexCoded, buff, bufferLen);

    // Remove PKCS#1 1.5 padding.
    if (this->eme == "EME-PKCS1-v1_5"){
        int paddingStatus = 0;
        ssize_t newSize = ShsmUtils::removePkcs15Padding(buff, decHexLen / 2, buff, decHexLen / 2, &paddingStatus);
        if (newSize < 0){
            ERROR_MSG("decryptCall", "Decrypt error, padding cannot be removed.")
            return errRet;
        }

        bufferLen = newSize;

    } else {
        ERROR_MSG("decryptCall", "Padding cannot be determined.");
        return errRet;
    }

    // Allocate new secure vector and return it.
    return Botan::SecureVector<Botan::byte>(buff, bufferLen);
}

Botan::SecureVector<Botan::byte> PK_Decryptor_EME_Remote::dec(const Botan::byte byte[], size_t t) const {
    int status = 0;
    Botan::SecureVector<Botan::byte> ret = this->decryptCall(byte, t, &status);
    return ret;
}
