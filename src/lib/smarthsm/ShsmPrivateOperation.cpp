//
// Created by Dusan Klinec on 16.04.16.
//

#include "ShsmPrivateOperation.h"
#include "PK_Decryptor_EME_Remote.h"
#include "ShsmUtils.h"
#include <botan/engine.h>
#include <botan/pk_ops.h>
#include <botan/rsa.h>

using namespace Botan;

#define TAG "ShsmRsaPrivateOperation: "
BigInt ShsmPrivateOperation::private_op(const BigInt& m) const
{
    // TODO: refactor to a separate ProcessData request.
    SecureVector<byte> input = BigInt::encode(m);
    const byte * inputBuff = input.begin();
    const size_t inputSize = input.size();

#ifdef EB_DEBUG
    {std::string origPlainStr = ShsmApiUtils::bytesToHex(inputBuff, inputSize);
    DEBUG_MSGF((TAG"Original size: %lu, Plaintext: [%s]", inputSize, origPlainStr.c_str()));}
#endif

    // Generate JSON request for decryption.
    BigInt errRet = BigInt(0);
    Json::Value json = ShsmUtils::getRequestDecrypt(&this->privKey, inputBuff, inputSize);

    // Perform the request.
    std::shared_ptr<ShsmUserObjectInfo> uo = this->privKey.getUo();

    // Request with retry.
    SoftSlot * slot = uo->getSlot();
    Retry retry = slot != nullptr ? slot->getRetry() : Retry();

    Json::Value root = ShsmUtils::requestWithRetry(retry, uo->resolveHostname().c_str(),
                                uo->resolvePort(),
                                json);
    if (root.isNull()){
        DEBUG_MSGF((TAG"SHSM network request result failed"));
        return errRet;
    }

#ifdef EB_DEBUG
    {std::string response = ShsmApiUtils::json2string(root);
    DEBUG_MSGF((TAG"Request [%s]", response.c_str()));}
#endif

    // Process result.
    std::string rawResult = root["result"].asString();
    std::string resultString = ShsmApiUtils::removeWhiteSpace(rawResult);
    if (resultString.empty() || resultString.length() < 4){
        ERROR_MSG("decryptCall", "Response string is too short.");
        return errRet;
    }

    // Read prefix, first 4 characters (2 bytes). unsigned integer.
    // Denotes number of bytes of plain data. Usually 0.
    unsigned long prefix = ShsmApiUtils::getInt16FromHexString(resultString.c_str());

    // Strip suffix of the key beginning with "Packet"
    size_t pos = resultString.rfind("Packet", std::string::npos);
    std::string decryptedHexCoded = resultString.substr(4 + prefix*2,
                                                        pos == std::string::npos ? resultString.length() - 4 : pos - 4 - prefix*2);
#ifdef EB_DEBUG
    DEBUG_MSGF((TAG"Response, prefix: %lu, hexcoded AES ciphertext: [%s]", prefix, resultString.c_str()));
    DEBUG_MSGF((TAG"Response, without prefix/suffix [%s]", decryptedHexCoded.c_str()));
#endif

    // Allocate memory buffer for decrypted block, convert from hexa string coding to bytes
    const size_t decHexLen = decryptedHexCoded.length();
    const size_t bufferLen = decHexLen / 2;
    Botan::byte * buff = (Botan::byte *) malloc(sizeof(Botan::byte) * bufferLen);
    size_t buffSize = ShsmApiUtils::hexToBytes(decryptedHexCoded, buff, bufferLen);

#ifdef EB_DEBUG
    {DEBUG_MSGF((TAG"To AES-decrypt, bufflen: %lu, buffsize: %lu", bufferLen, buffSize));
    std::string toDecryptStr = ShsmApiUtils::bytesToHex(buff, buffSize);
    DEBUG_MSGF((TAG"To AES-decrypt string: %s", toDecryptStr.c_str()));}
#endif

    // AES-256-CBC-PKCS7 decrypt
    Botan::SecureVector<Botan::byte> * decData = NULL;
    int decStatus = ShsmUtils::readProtectedData(
            buff,
            buffSize,
            *(uo->getEncKey()),
            *(uo->getMacKey()),
            &decData);

    if (decStatus != 0){
        DEBUG_MSGF((TAG"Failed to read protected data"));
        return errRet;
    }

#ifdef EB_DEBUG
    {std::string decStr = ShsmApiUtils::bytesToHex(decData->begin(), decData->size());
    DEBUG_MSGF((TAG"RSA-decrypted string: %s", decStr.c_str()));}
#endif

    // Adjust data size, padding / aux info may got stripped.
    buffSize = decData->size();
    free(buff);

    // PKCS1.5 padding removal was here, but in pure RSA decrypt operation no padding is added.
#ifdef EB_DEBUG
    DEBUG_MSGF((TAG"Decrypted data length: %lu", decData->size()));
    Botan::byte * b = decData->begin();
    DEBUG_MSGF((TAG"Decrypted, returning buffer of size: %lu %x %x, size of decData: %lu", buffSize, b, b+1, decData->size()));
#endif

    // Allocate new secure vector and return it.
    BigInt intResult = BigInt::decode(decData->begin(), buffSize);
    delete decData;

    return intResult;
}

