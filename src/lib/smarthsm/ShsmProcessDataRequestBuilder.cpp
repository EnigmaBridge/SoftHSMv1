//
// Created by Dusan Klinec on 16.04.16.
//

#include <src/lib/log.h>
#include <botan/types.h>
#include <botan/symkey.h>
#include "ShsmApiUtils.h"
#include "ShsmProcessDataRequestBuilder.h"
#include "ShsmProcessDataRequest.h"
#include "ShsmUserObjectInfo.h"
#include "ShsmUtils.h"

#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <iomanip>
#include <string>
#include <iomanip>
#include <iostream>     // std::cout
#include <sstream>      // std::ostringstream
#include <json.h>
#include <botan/block_cipher.h>
#include <botan/symkey.h>
#include <botan/b64_filt.h>
#include <botan/engine.h>
#include <botan/lookup.h>
#define TAG "ShsmUtils: "
#define MACTAGLEN 16


ShsmProcessDataRequest *ShsmProcessDataRequestBuilder::buildProcessDataRequest(const Botan::byte *const body,
                                                                               size_t bodyLen,
                                                                               ShsmUserObjectInfo *uo,
                                                                               t_eb_request_type requestType,
                                                                               Botan::byte *bodyBuff,
                                                                               size_t bodyBuffLen,
                                                                               int *statusCode)
{
    if (!uo){
        ERROR_MSG("buildProcessDataRequest", "Empty UO");
        return nullptr;
    }

    if (requestType >= EB_REQUEST_TYPE_MAX){
        ERROR_MSG("buildProcessDataRequest", "Request type invalid");
        return nullptr;
    }

    if (bodyBuff != NULL && bodyBuffLen < (bodyLen + 128)){
        ERROR_MSG("buildProcessDataRequest", "Body buffer too small");
        if (statusCode) *statusCode = -3;
        return nullptr;
    }

    ShsmProcessDataRequest * request = new ShsmProcessDataRequest();

    // 8B freshness nonce first.
    ShsmApiUtils::generateNonceBytes(request->getNonceBytes(), SHSM_FRESHNESS_NONCE_LEN);
    std::string finalNonce = ShsmApiUtils::bytesToHex(request->getNonceBytes(), SHSM_FRESHNESS_NONCE_LEN);

    // Request body
    Json::Value jReq;
    jReq["function"] = "ProcessData";
    jReq["version"] = "1.0";
    jReq["objectid"] = ShsmUtils::buildApiObjectId(uo);
    jReq["nonce"] = finalNonce;
    const int keyId = (int) uo->getKeyId();

    // TODO: remote, already done above...
//    // Object id, long to string.
//    char buf[16] = {0};
//    snprintf(buf, 16, "%d", keyId);
//    jReq["objectid"] = buf;

    std::ostringstream dataBuilder;

    // _0000 is the length of plain data, 2B.
    dataBuilder << "Packet0_" << EB_REQUEST_TYPES[requestType] << "_0000";

    // AES-256-CBC-PKCS7 encrypt data for decryption.
    // IV is null for now, freshness nonce is used as IV, some kind of.
    Botan::byte iv[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    const std::shared_ptr<BotanSecureByteKey> encKey = uo->getEncKey();
    const std::shared_ptr<BotanSecureByteKey> macKey = uo->getMacKey();
    if (!encKey || !macKey){
        ERROR_MSG("buildProcessDataRequest", "Empty keys");
        if (statusCode) *statusCode = -4;
        delete request;
        return nullptr;
    }

    Botan::SymmetricKey aesKey(*encKey);
    Botan::SymmetricKey aesMacKey(*macKey);
    Botan::InitializationVector aesIv(iv, 16);

    // Encryption & MAC encrypted ciphertext
    Botan::Pipe pipe(
            Botan::get_cipher("AES-256/CBC/PKCS7", aesKey, aesIv, Botan::ENCRYPTION),
            new Botan::Fork(
                    // output from encryption goes here, messageId=0
                    0,
                    // output of encryption goes to MAC, messageId=1.
                    new Botan::MAC_Filter("CBC-MAC(AES-256)", aesMacKey)
            ));

    pipe.start_msg();

#ifdef EB_DEBUG
    std::string processDataInputStr = ShsmApiUtils::bytesToHex(body, bodyLen);
    DEBUG_MSGF((TAG"ProcessData input req: [%s]", processDataInputStr.c_str()));
#endif

    // Write header of form 0x1f | <UOID-4B>
    Botan::byte dataHeader[5] = {0x1f, 0x0, 0x0, 0x0, 0x0};
    ShsmApiUtils::writeInt32ToBuff((unsigned long) keyId, dataHeader + 1);
    pipe.write(dataHeader, 5);
    pipe.write(request->getNonceBytes(), SHSM_FRESHNESS_NONCE_LEN); // freshness nonce 8B
    pipe.write(body, bodyLen);
    pipe.end_msg();

#ifdef EB_DEBUG
    DEBUG_MSGF((TAG"DataHeader: %x %x %x %x %x keyId: %lu", dataHeader[0], dataHeader[1], dataHeader[2], dataHeader[3], dataHeader[4], (unsigned long)keyId));
#endif

    // Read the output of the Botan pipe.
    Botan::byte * buff = bodyBuff;
    if (buff == NULL) {
        buff = (Botan::byte *) malloc(sizeof(Botan::byte) * (bodyLen + 128));
        if (buff == NULL) {
            ERROR_MSG("getRequestDecrypt", "Could not allocate enough memory for encryption operation");
            if (statusCode) *statusCode = -2;
            delete request;
            return nullptr;
        }
    }

    // Read encrypted data from the pipe.
    size_t cipLen = pipe.read(buff, (bodyLen + 128), 0);
#ifdef EB_DEBUG
    DEBUG_MSGF((TAG"Encrypted message len: %lu", cipLen));
#endif

    // Read MAC on encrypted data from the pipe
    size_t macLen = pipe.read(buff+cipLen, (bodyLen + 128 - cipLen), 1);
#ifdef EB_DEBUG
    DEBUG_MSGF((TAG"MAC message len: %lu", macLen));
#endif

    // Add hex-encoded input data here.
    dataBuilder << ShsmApiUtils::bytesToHex(buff, cipLen+macLen);

    // Deallocate temporary buffer.
    if (bodyBuff == NULL) {
        free(buff);
    }

    // ProcessData - add data part.
    jReq["data"] = dataBuilder.str();
    request->setRequest(jReq);

    if (statusCode) *statusCode = 0;
    return request;
}

ShsmProcessDataRequest * ShsmProcessDataRequestBuilder::buildProcessDataRequest(const Botan::byte *const body, size_t bodyLen) {
    return buildProcessDataRequest(body, bodyLen, this->uo, this->requestType, this->bodyBuff, this->bodyBuffLen, &(this->statusCode));
}