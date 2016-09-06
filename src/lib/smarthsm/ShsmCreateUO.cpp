//
// Created by Dusan Klinec on 06.09.16.
//

#include <src/lib/log.h>
#include <botan/lookup.h>
#include "ShsmCreateUO.h"
#include "ShsmUtils.h"
#include "Retry.h"
#define TAG "ShsmCreateUO: "

Json::Value ShsmCreateUO::getDefaultTemplateRequestSpec() {
    using namespace createUO;

    Json::Value jReq;
    jReq["format"] = 1;
    jReq["protocol"] = 1;

    jReq["environment"] = "dev"; // shows whether the UO should be for production (live), test (pre-production testing), or dev (development)
    jReq["maxtps"] = "unlimited"; // maximum guaranteed TPS
    jReq["core"] = "empty"; // how many cards have UO loaded permanently
    jReq["persistence"] = "one_minute"; // once loaded onto card, how long will the UO stay there without use (this excludes the "core")
    jReq["priority"] = "default"; // this defines a) priority when the server capacity is fully utilised and it also defines how quickly new copies of UO are installed (pre-empting icreasing demand)
    jReq["separation"] = "time"; // "complete" = only one UO can be loaded on a smartcard at one one time
    jReq["bcr"] = consts::yes; // "yes" will ensure the UO is replicated to provide high availability for any possible service disruption
    jReq["unlimited"] = consts::yes; //  if "yes", we expect the data starts with an IV to initialize decryption of data - this is for communication security
    jReq["clientiv"] = consts::yes; // if "yes", we expect the data starting with a diversification 16B for communication keys
    jReq["clientdiv"] = consts::no;
    jReq["resource"] = "global";
    jReq["credit"] = 32677; // <1-32767>, a limit a seed card can provide to the EB service

    Json::Value jGen;
    jGen[consts::commkey] = consts::gen::SERVER_RANDOM;
    jGen[consts::billingkey] = consts::gen::SERVER_RANDOM;
    jGen[consts::appkey] = consts::gen::SERVER_RANDOM;

    jReq[consts::generation] = jGen;
    return jReq;
}

Json::Value ShsmCreateUO::getTemplateRequestSpec(const Json::Value *spec) {
    Json::Value ret(getDefaultTemplateRequestSpec());

    if (spec != nullptr) {
        ShsmUtils::merge(ret, *spec);
    }

    return ret;
}

void ShsmCreateUO::setType(Json::Value *spec, int type) {
    if (spec == nullptr){
        return;
    }

    char buff[16];
    snprintf(buff, 16, "%x", type);
    (*spec)[createUO::consts::type] = buff;
}

Json::Value ShsmCreateUO::getTemplateRequest(SoftSlot *slot, const Json::Value *spec) {
    // Request body
    Json::Value jReq;
    jReq["function"] = "GetUserObjectTemplate";
    jReq["version"] = "1.0";
    jReq["objectid"] = ShsmApiUtils::generateApiObjectId(slot->apiKey, 0x1);
    jReq["nonce"] = ShsmApiUtils::generateNonce(8);
    jReq["data"] = getTemplateRequestSpec(spec);
    return jReq;
}

Json::Value ShsmCreateUO::templateRequest(SoftSlot *slot, const Json::Value *spec) {
    int curRetry = 0;
    Retry retry;
    Json::Value errRet(0); // null error response.

    if (slot->config != nullptr) {
        retry.configure(*slot->config);
    }

    // Template request, nonce will be regenerated.
    Json::Value req = ShsmCreateUO::getTemplateRequest(slot, spec);

    // Do the request with retry. isNull() == true in case of a fail.
    Json::Value resp = ShsmUtils::requestWithRetry(retry, slot->host.c_str(), slot->getEnrollPort(), req);

    return resp;
}

ShsmImportRequest *ShsmCreateUO::processTemplate(SoftSlot *slot,
                                                 const Json::Value * tplReqSpec,
                                                 const Json::Value * tplResp,
                                                 int *statusCode)
{
    // Minor sanity check.
    if (tplResp == nullptr
        || tplResp->isNull()
        || (*tplResp)["result"].isNull()
        || (*tplResp)["result"]["encryptionoffset"].isNull()
        || (*tplResp)["result"]["flagoffset"].isNull()
        || (*tplResp)["result"]["keyoffsets"].isNull()
        || (*tplResp)["result"]["importkeys"].isNull()
        || (*tplResp)["result"]["template"].isNull())
    {
        ERROR_MSGF((TAG"Template response invalid: [%s]", ShsmApiUtils::json2string(*tplResp)));
        if (statusCode) *statusCode = -1;
        return nullptr;
    }

    // Shortcut
    const Json::Value & tpl = (*tplResp)["result"];

    // Generate comm keys
    std::unique_ptr<ShsmImportRequest> req(new ShsmImportRequest());
    req->generateCommKeys();

    // Generate template in bytes.
    req->setTpl(tpl["template"].asString());
    BotanSecureByteVector & tplVector = req->getTpl();
    Botan::byte * const tplBuff = tplVector;

    // Fill in the keys - only comm keys.
    const Json::Value & keysOffset = tpl["keyoffsets"];
    for(unsigned int index=0; index < keysOffset.size(); ++index) {
        const Json::Value cKeyOff = keysOffset[index];
        if (cKeyOff.isNull()
            || cKeyOff["type"].isNull()
            || cKeyOff["length"].isNull()
            || cKeyOff["offset"].isNull())
        {
            ERROR_MSGF(TAG"Key offset broken");
            if (statusCode) *statusCode = -2;
            return nullptr;
        }

        const std::string keyType = cKeyOff["type"].asString();
        Botan::byte const * commKey = NULL;
        int commKeyLen = -1;

        // We accept only comm keys here, deal with it.
        if (keyType == "comenc"){
            commKey = req->getCommEncKey();
            commKeyLen = SHSM_COMM_KEY_ENC_SIZE;

        } else if (keyType == "commac"){
            commKey = req->getCommMacKey();
            commKeyLen = SHSM_COMM_KEY_MAC_SIZE;

        } else {
            continue;
        }

        // Copy the given key to appropriate place in the template.
        if (commKeyLen*8 != cKeyOff["length"].asInt()){
            ERROR_MSGF((TAG"Key length does not match, %d vs %d for type %s", commKeyLen*8, cKeyOff["length"].asInt(), keyType.c_str()));
            if (statusCode) *statusCode = -3;
            return nullptr;
        }

        memcpy(tplBuff + (cKeyOff["offset"].asInt() / 8), commKey, (size_t)commKeyLen);
    }

    // Set flags representing generation way accordingly - commkeys are client generated, app key is server generated.
    int flagOffset = tpl["flagoffset"].asInt() / 8;
    tplBuff[flagOffset + 1] &= ~0x8;


    // Encrypt part of the buffer.
    const int encOffset = tpl["encryptionoffset"].asInt() / 8;
    BotanSecureByteVector encryptedTemplate;
    int res = encryptTemplate(req->getCommEncKey(), req->getCommMacKey(), encOffset, tplVector, encryptedTemplate);
    if (res != 0){
        ERROR_MSGF((TAG"Encryption failed (sym)"));
        if (statusCode) *statusCode = -4;
        return nullptr;
    }

    // RSA encryption.
    


    ShsmImportRequest * toReturn = req.get();
    req.release();
    return toReturn;
}

int ShsmCreateUO::encryptTemplate(const BotanSecureByteKey & encKey, const BotanSecureByteKey & macKey,
                                  size_t encOffset,
                                  BotanSecureByteVector & buffer,
                                  BotanSecureByteVector & dest)
{
    // AES-256-CBC-PKCS7 encrypt data for decryption.
    // IV is null for now, freshness nonce is used as IV, some kind of.
    Botan::byte iv[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    Botan::SymmetricKey aesKey(encKey);
    Botan::SymmetricKey aesMacKey(macKey);
    Botan::InitializationVector aesIv(iv, 16);

    // Encryption & MAC encrypted ciphertext
    Botan::Pipe pipe(Botan::get_cipher("AES-256/CBC/PKCS7", aesKey, aesIv, Botan::ENCRYPTION));
    pipe.start_msg();

#ifdef EB_DEBUG
    {std::string dumpStr = ShsmApiUtils::bytesToHex(buffer, buffer.size());
    DEBUG_MSGF((TAG"To process buffer: [%s]", dumpStr.c_str()));}
#endif

    // Write header of form 0x1f | <UOID-4B>
    pipe.write(buffer+encOffset, (size_t)buffer.size() - encOffset);
    pipe.end_msg();

    // Secure buffer.
    const size_t encryptedDataBuffSize = buffer.size() - encOffset+128;
    BotanSecureByteVector encryptedData(encryptedDataBuffSize);

    // Read encrypted data from the pipe.
    size_t cipLen = pipe.read(encryptedData, (size_t)encryptedDataBuffSize, 0);
#ifdef EB_DEBUG
    DEBUG_MSGF((TAG"Encrypted message len: %lu", cipLen));
#endif

    // Mac the whole buffer, with padding.
    Botan::Pipe pipeMac(new Botan::MAC_Filter("CBC_MAC(AES-256/PKCS7)", aesMacKey));
    pipeMac.start_msg();
    pipeMac.write(buffer, encOffset);
    pipeMac.write(encryptedData, cipLen);
    pipeMac.end_msg();

    // Read MAC on encrypted data from the pipe
    size_t macLen = pipeMac.read(encryptedData+cipLen, encryptedDataBuffSize - cipLen);

#ifdef EB_DEBUG
    DEBUG_MSGF((TAG"MAC message len: %lu", macLen));
#endif

    dest.resize(cipLen+macLen+encOffset);
    memcpy(dest, buffer, encOffset);
    memcpy(dest+encOffset, encryptedData, cipLen+macLen);
    return 0;
}




