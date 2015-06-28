//
// Created by Dusan Klinec on 18.06.15.
//

#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <iomanip>
#include <string>
#include <botan/eme.h>
#include <botan/eme_pkcs.h>
#include "PK_Decryptor_EME_Remote.h"
#include "ShsmUtils.h"
#include "ShsmApiUtils.h"
#include "ShsmNullRng.h"

#define TAG "SHSMDecryptor: "
PK_Decryptor_EME_Remote::PK_Decryptor_EME_Remote(ShsmPrivateKey * key,
                                                 const std::string &eme,
                                                 const SoftSlot *curSlot) : PK_Decryptor()
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

void PK_Decryptor_EME_Remote::testCallWithByte(Botan::byte plaintextByte, bool pkcs15padding) const {
    const size_t preee = 1;
    DEBUG_MSGF(("Testing dec() call with plaintext byte 0x%x, padding: %d", plaintextByte, pkcs15padding));

    // Prepare zero vector here.
    Botan::byte inpPlain[256];
    bzero(inpPlain, sizeof(Botan::byte) * 256);
    inpPlain[0] = plaintextByte;

    // Extract public key from the database.
    Botan::BigInt bigN = this->privKey->getBigN();
    Botan::BigInt bigE = this->privKey->getBigE();
    Botan::RSA_PublicKey rsaPub(bigN, bigE);

    Botan::PK_Encryptor_EME rsaEncryptor(rsaPub, pkcs15padding ? "EME-PKCS1-v1_5" : "Raw");
    Botan::AutoSeeded_RNG autoRng;
    ShsmNullRng nullRng2;
    Botan::SecureVector<Botan::byte> toDec = rsaEncryptor.encrypt(inpPlain, preee, nullRng2);

    size_t sizeN = bigN.bytes();
    size_t sizeE = bigE.bytes();
    Botan::byte * binN = (Botan::byte *) malloc(sizeof(Botan::byte) * sizeN);
    Botan::byte * binE = (Botan::byte *) malloc(sizeof(Botan::byte) * sizeE);
    bigN.binary_encode(binN);
    bigE.binary_encode(binE);

    std::string modulusStr = ShsmApiUtils::bytesToHex(binN, sizeN);
    std::string expStr     = ShsmApiUtils::bytesToHex(binE, sizeE);
    DEBUG_MSGF(("PUB_N: 0x%s\n", modulusStr.c_str()));
    DEBUG_MSGF(("PUB_E: 0x%s\n", expStr.c_str()));

    std::string plainStr = ShsmApiUtils::bytesToHex(inpPlain, preee);
    std::string toDecStr = ShsmApiUtils::bytesToHex(toDec.begin(), toDec.size());
    DEBUG_MSGF(("RSA encryption maximum input size: %lu", rsaEncryptor.maximum_input_size()));
    DEBUG_MSGF(("RSA Plaintext,  size: %lu, Plaintext=[%s]", preee, plainStr.c_str()));
    DEBUG_MSGF(("RSA Ciphertext, size: %lu, RSA_ENC(fff..f)=[%s]", toDec.size(), toDecStr.c_str()));

    // Do the request
    int status = 0;
    Botan::SecureVector<Botan::byte> secVect = this->decryptCall(toDec.begin(), toDec.size(), &status);

    // Process the response, check with the input given.
    Botan::byte * b = secVect.begin();
    const size_t vsize = secVect.size();
    if (vsize == 1){
        if (b[0] == plaintextByte) {
            INFO_MSGF(("RSA Decrypted plaintext of size 1 is correct!"));
            return;
        } else {
            ERROR_MSGF(("RSA Decrypted plaintext of size 1 invalid. Got 0x%x expected 0x%x", b[0], plaintextByte));
            return;
        }
    }

    // Full text response.
    if (vsize != 256){
        ERROR_MSGF(("RSA Decrypted size invalid, size=%lu", vsize));
        return;
    }

    for(int i=0; i<255; i++){
        if (b[i] != 0x0){
            ERROR_MSG("testCall", "Invalid plaintext body");
            return;
        }
    }

    if (b[255] != plaintextByte){
        ERROR_MSG("testCall", "Invalid plaintext body - missing the plaintext byte");
        return;
    } else {
        INFO_MSGF(("Everything is correct!"));
    }
}

Botan::SecureVector<Botan::byte> PK_Decryptor_EME_Remote::decryptCall(const Botan::byte byte[], size_t t, int * status) const {
    std::string origPlainStr = ShsmApiUtils::bytesToHex(byte, t);
    DEBUG_MSGF((TAG"Original size: %lu, Plaintext: [%s]", t, origPlainStr.c_str()));

    // Generate JSON request for decryption.
    Botan::SecureVector<Botan::byte> errRet = Botan::SecureVector<Botan::byte>(0);
    std::string json = ShsmUtils::getRequestDecrypt(this->privKey, this->connectionConfig->getKey(), byte, t, "");

    // Perform the request.
    int reqResult = 0;
    std::string response = ShsmApiUtils::request(this->connectionConfig->getMHost().c_str(),
                                                 this->connectionConfig->getMPort(),
                                                 json, &reqResult);
    if (reqResult != 0){
        DEBUG_MSGF((TAG"SHSM network request result failed, code=%d", reqResult));
        return errRet;
    }

    DEBUG_MSGF((TAG"Request [%s]", json.c_str()));

    // Parse response, extract result, return it.
    Json::Value root;   // 'root' will contain the root value after parsing.
    Json::Reader reader;
    bool parsedSuccess = reader.parse(response, root, false);
    if(!parsedSuccess) {
        ERROR_MSG("decryptCall", "Could not read data from socket");
        ERROR_MSGF((TAG"Response: [%s]", response.c_str()));
        return errRet;
    }

    // Check status code.
    int resultCode = ShsmApiUtils::getStatus(root);
    if (resultCode != 9000){
        ERROR_MSG("decryptCall", "Result code is not 9000, cannot decrypt");
        ERROR_MSGF((TAG"Result code: %d, response: [%s]", resultCode, response.c_str()));
        return errRet;
    }

    // Process result.
    std::string rawResult = root["result"].asString();
    std::string resultString = ShsmApiUtils::removeWhiteSpace(rawResult);
    if (resultString.empty() || resultString.length() < 4){
        ERROR_MSG("decryptCall", "Response string is too short.");
        return errRet;
    }

    // Read prefix, first 4 bytes. unsigned long?
    unsigned long prefix = ShsmApiUtils::getLongFromString(resultString.c_str());

    // Strip suffix of the key beginning with "Packet"
    size_t pos = resultString.rfind("Packet", std::string::npos);
    std::string decrytpedHexCoded = resultString.substr(4 + prefix,
                                                        pos == std::string::npos ? resultString.length() - 4 : pos - 4 - prefix);

    DEBUG_MSGF((TAG"Response, prefix: %lu, hexcoded AES ciphertext: [%s]", prefix, resultString.c_str()));
    DEBUG_MSGF((TAG"Response, without prefix/suffix [%s]", decrytpedHexCoded.c_str()));

    // Allocate memory buffer for decrypted block, convert from hexa string coding to bytes
    const size_t decHexLen = decrytpedHexCoded.length();
    const size_t bufferLen = decHexLen / 2;
    Botan::byte * buff = (Botan::byte *) malloc(sizeof(Botan::byte) * bufferLen);
    size_t buffSize = ShsmApiUtils::hexToBytes(decrytpedHexCoded, buff, bufferLen);
    DEBUG_MSGF((TAG"To AES-decrypt, bufflen: %lu, buffsize: %lu", bufferLen, buffSize));

    std::string toDecryptStr = ShsmApiUtils::bytesToHex(buff, buffSize);
    DEBUG_MSGF((TAG"To AES-decrypt string: %s", toDecryptStr.c_str()));

    // AES-256-CBC-PKCS7 decrypt
    int decStatus = 0;
    Botan::SecureVector<Botan::byte> decData = ShsmUtils::readProtectedData(buff, buffSize, this->connectionConfig->getKey(), &decStatus);

    std::string decStr = ShsmApiUtils::bytesToHex(decData.begin(), decData.size());
    DEBUG_MSGF((TAG"RSA-decrypted string: %s", decStr.c_str()));

    // Adjust data size, padding / aux info may got stripped.
    buffSize = decData.size();
    free(buff);

    DEBUG_MSGF((TAG"Decrypted data length: %lu", decData.size()));

    // Remove PKCS#1 1.5 padding.
    if (this->eme == "EME-PKCS1-v1_5"){
        int paddingStatus = 0;
        // TODO: use unpadding scheme EME_PKCS1v15 eme_pkcs.h
        ssize_t newSize = ShsmUtils::removePkcs15Padding(decData.begin(), buffSize, decData.begin(), bufferLen, &paddingStatus);
        if (newSize < 0){
            DEBUG_MSG("decryptCall", "Decrypt error, padding cannot be removed.")
        } else {
            buffSize = (size_t) newSize;
        }

    } else {
        ERROR_MSG("decryptCall", "Padding cannot be determined.");
        return errRet;
    }

    Botan::byte * b = decData.begin();
    DEBUG_MSGF((TAG"Decrypted, returning buffer of size: %lu %x %x, size of decData: %lu", buffSize, b, b+1, decData.size()));

    // Allocate new secure vector and return it.
    return Botan::SecureVector<Botan::byte>(decData.begin(), buffSize);
}

Botan::SecureVector<Botan::byte> PK_Decryptor_EME_Remote::dec(const Botan::byte byte[], size_t t) const {
    // <test>
//    this->testCallWithByte(0x0, false);
//    this->testCallWithByte(0x1, false);
//    this->testCallWithByte(0x2, false);
//    this->testCallWithByte(0x0, true);
//    this->testCallWithByte(0x1, true);
//    this->testCallWithByte(0x2, true);
    // </test>

    int status = 0;
    Botan::SecureVector<Botan::byte> ret = this->decryptCall(byte, t, &status);
//    Botan::SecureVector<Botan::byte> ret(byte, t);
//    Botan::SecureVector<Botan::byte> ret(0);

    Botan::byte * b = ret.begin();
    DEBUG_MSGF((TAG"dec(): Decrypted, returning buffer of size: %lu %x %x", ret.size(), b, b+1));
    return ret;
}
