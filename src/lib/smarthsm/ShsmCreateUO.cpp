//
// Created by Dusan Klinec on 06.09.16.
//

#include <src/lib/log.h>
#include <botan/lookup.h>
#include "ShsmCreateUO.h"
#include "ShsmUtils.h"
#include "Retry.h"
#define TAG "ShsmCreateUO: "

// Constants.
namespace createUO {
    namespace consts {
        const char * const type = "type";
        const char * const generation = "generation";
        const char * const commkey = "commkey";
        const char * const billingkey = "billingkey";
        const char * const appkey = "appkey";

        const char * const yes = "yes";
        const char * const no = "no";
    }
}

Json::Value ShsmCreateUO::getDefaultTemplateRequestSpec() {
    using namespace createUO;

    Json::Value jReq;
    jReq["format"] = 1;
    jReq["protocol"] = 1;

    jReq["environment"] = "dev"; // shows whether the UO should be for production (live), test (pre-production testing), or dev (development)
    jReq["maxtps"] = "one"; // maximum guaranteed TPS
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
    jGen[consts::commkey] = consts::gen::CLIENT;
    jGen[consts::billingkey] = consts::gen::LEGACY_RANDOM;
    jGen[consts::appkey] = consts::gen::LEGACY_RANDOM;

    jReq[consts::generation] = jGen;
    return jReq;
}

Json::Value ShsmCreateUO::getTemplateRequestSpec(const Json::Value *spec) {
    Json::Value ret(getDefaultTemplateRequestSpec());

    if (spec != nullptr && !spec->isNull()) {
        ShsmUtils::merge(ret, *spec);
    }

    return ret;
}

Json::Value ShsmCreateUO::getTemplateRequestSpec(SoftSlot * slot) {
    Json::Value cfg(0);
    if (slot != nullptr
        && slot->getConfig() != nullptr
        && !slot->getConfig()->isNull())
    {
        Json::Value & slotConf = *(slot->getConfig());
        if (!slotConf["createTpl"].isNull()){
            cfg = slotConf["createTpl"];
        }
    }

    return ShsmCreateUO::getTemplateRequestSpec(&cfg);
}

void ShsmCreateUO::setType(Json::Value *spec, int type) {
    if (spec == nullptr){
        return;
    }

    // Comm keys are generated on our side (20), appkey is server generated
    type |= 1<<20;
    type &= ~(1<<21);

    char buff[16];
    snprintf(buff, 16, "%x", type);
    (*spec)[createUO::consts::type] = Json::Value(buff);

    // Generation - set accordingly.
    (*spec)[createUO::consts::generation][createUO::consts::appkey] = createUO::consts::gen::LEGACY_RANDOM;
    (*spec)[createUO::consts::generation][createUO::consts::commkey] = createUO::consts::gen::CLIENT;
}

int ShsmCreateUO::setRsaType(Json::Value * spec, int bitSize){
    switch (bitSize){
        case 1024:
            ShsmCreateUO::setType(spec, createUO::consts::uoType::RSA1024DECRYPT_NOPAD);
            return 0;

        case 2048:
            ShsmCreateUO::setType(spec, createUO::consts::uoType::RSA2048DECRYPT_NOPAD);
            return 0;

        default:
            WARNING_MSGF((TAG"Unsupported RSA key size %d", bitSize));
            return -1;
    }
}

Json::Value ShsmCreateUO::getTemplateRequest(SoftSlot *slot, const Json::Value *spec) {
    // Request body
    Json::Value jReq;
    jReq["function"] = "GetUserObjectTemplate";
    jReq["version"] = "1.0";
    jReq["objectid"] = ShsmApiUtils::generateApiObjectId(slot->apiKey, 0x1);
    jReq["nonce"] = ShsmApiUtils::generateNonce(16);
    jReq["data"] = getTemplateRequestSpec(spec);
    return jReq;
}

Json::Value ShsmCreateUO::templateRequest(SoftSlot *slot, const Json::Value *spec, int * status) {
    // Template request, nonce will be regenerated.
    Json::Value req = ShsmCreateUO::getTemplateRequest(slot, spec);

    // Do the request with retry. isNull() == true in case of a fail.
    Json::Value resp = ShsmUtils::requestWithRetry(slot->getRetry(), slot->host.c_str(), slot->getEnrollPort(), req, status);

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
        || (*tplResp)["result"]["template"].isNull()
        || (*tplResp)["result"]["objectid"].isNull())
    {
        ERROR_MSGF((TAG"Template response invalid: [%s]",
                (tplResp == nullptr || tplResp->isNull()) ? "" : ShsmApiUtils::json2string(*tplResp).c_str()
        ));
        if (statusCode) *statusCode = -1;
        return nullptr;
    }

    // unused, handy later.
    (void)slot;
    (void)tplReqSpec;

    // Shortcut
    const Json::Value & tpl = (*tplResp)["result"];

    // Generate comm keys
    std::unique_ptr<ShsmImportRequest> req(new ShsmImportRequest());
    req->generateCommKeys();

    // Generate template in bytes.
    BotanSecureByteVector tplVector;
    int res = ShsmCreateUO::parseHexToVector(tpl["template"].asString(), tplVector);
    if (res != 0){
        if (statusCode) *statusCode = -9;
        return nullptr;
    }

    Botan::byte * const tplBuff = tplVector.begin();

    // Fill in the keys - only comm keys.
    const Json::Value & keysOffset = tpl["keyoffsets"];
    for(unsigned int index=0; index < keysOffset.size(); ++index) {
        const Json::Value cKeyOff = keysOffset[index];
        if (cKeyOff.isNull()
            || cKeyOff["type"].isNull()
            || cKeyOff["length"].isNull()
            || cKeyOff["offset"].isNull())
        {
            ERROR_MSGF((TAG"Key offset broken"));
            if (statusCode) *statusCode = -2;
            return nullptr;
        }

        const std::string keyType = cKeyOff["type"].asString();
        Botan::byte const * commKey = NULL;
        int commKeyLen = -1;

        // We accept only comm keys here, deal with it.
        if (keyType == "comenc"){
            commKey = req->getCommEncKey().begin();
            commKeyLen = SHSM_COMM_KEY_ENC_SIZE;

        } else if (keyType == "commac"){
            commKey = req->getCommMacKey().begin();
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

    // Random encryption keys.
    BotanSecureByteKey tplEncKey = BotanSecureByteVector(32);
    BotanSecureByteKey tplMacKey = BotanSecureByteVector(32);
    ShsmApiUtils::rng().randomize(tplEncKey, 32);
    ShsmApiUtils::rng().randomize(tplMacKey, 32);

    // Encrypt part of the buffer.
    const size_t encOffset = (size_t)tpl["encryptionoffset"].asInt() / 8;
    BotanSecureByteVector encryptedTemplate;
    res = encryptTemplate(tplEncKey, tplMacKey, encOffset, tplVector, encryptedTemplate);
    if (res != 0){
        ERROR_MSGF((TAG"Encryption failed (sym) %d", res));
        if (statusCode) *statusCode = -4;
        return nullptr;
    }

    // Prepare buffer for RSA encryption.
    Json::Value iKey = ShsmCreateUO::getBestImportKey(tpl["importkeys"]);
    req->setImportKey(iKey);
    req->setObjectId(tpl["objectid"]);
    req->setAuthorization(tpl["authorization"]);

    BotanSecureByteVector rsaEncryptInput(tplEncKey.size() + tplMacKey.size() + 4);
    unsigned int uoid = ShsmApiUtils::getHexUint32FromJsonField(tpl["objectid"], &res);
    if (res != 0){
        ERROR_MSGF((TAG"Object id conversion failed %d", res));
        if (statusCode) *statusCode = -5;
        return nullptr;
    }

    ShsmApiUtils::writeInt32ToBuff(uoid, rsaEncryptInput.begin());
    memcpy(rsaEncryptInput.begin()+4,                  tplEncKey.begin(), tplEncKey.size());
    memcpy(rsaEncryptInput.begin()+4+tplEncKey.size(), tplMacKey.begin(), tplMacKey.size());

    // RSA encryption
    BotanSecureByteVector rsaEncrypted;
    res = encryptRSA(iKey, rsaEncryptInput, rsaEncrypted);
    if (res != 0){
        ERROR_MSGF((TAG"RSA encryption failed %d", res));
        if (statusCode) *statusCode = -6;
        return nullptr;
    }

    // Final template: 0xa1 | len-2B | RSA-ENC-BLOB | 0xa2 | len-2B | encrypted-maced-template
    BotanSecureByteVector finalTemplate(6 + rsaEncrypted.size() + encryptedTemplate.size());
    Botan::byte * finalTemplateBuff = finalTemplate.begin();

    int offset = 0;
    finalTemplateBuff[offset++] = 0xa1;
    ShsmApiUtils::writeInt16ToBuff((int)rsaEncrypted.size(), finalTemplateBuff+offset); offset+=2;
    memcpy(finalTemplateBuff+offset, rsaEncrypted.begin(), rsaEncrypted.size());        offset+=rsaEncrypted.size();

    finalTemplateBuff[offset++] = 0xa2;
    ShsmApiUtils::writeInt16ToBuff((int)encryptedTemplate.size(), finalTemplateBuff+offset); offset+=2;
    memcpy(finalTemplateBuff+offset, encryptedTemplate.begin(), encryptedTemplate.size());

    // Done
    req->setTplPrepared(finalTemplate);
    ShsmImportRequest * toReturn = req.get();
    req.release();

    if (statusCode) *statusCode = 0;
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
    {//std::string dumpStr = ShsmApiUtils::bytesToHex(buffer.begin(), buffer.size());
    DEBUG_MSGF((TAG"To process buffer len: [%d]", (int)buffer.size()));}
#endif

    // Write header of form 0x1f | <UOID-4B>
    pipe.write(buffer.begin() + encOffset, (size_t)buffer.size() - encOffset);
    pipe.end_msg();

    // Secure buffer - encryption result goes here.
    const size_t encryptedDataBuffSize = buffer.size() - encOffset+128;
    BotanSecureByteVector encryptedData(encryptedDataBuffSize);

    // Read encrypted data from the pipe.
    size_t cipLen = pipe.read(encryptedData.begin(), (size_t)encryptedDataBuffSize, 0);
#ifdef EB_DEBUG
    DEBUG_MSGF((TAG"Encrypted message len: %lu, plain length: %lu", cipLen, encOffset));
#endif

    size_t paddingSize = 16 - ((cipLen + encOffset) % 16);
    BotanSecureByteVector pkcs7Padding(paddingSize);
    for(unsigned i = 0; i < paddingSize; ++i){
        pkcs7Padding.begin()[i] = (Botan::byte)paddingSize;
    }

    // Mac the whole buffer, with padding.
    BotanSecureByteVector macBuffer(16);
    Botan::Pipe pipeMac(new Botan::MAC_Filter("CBC-MAC(AES-256)", aesMacKey));
    pipeMac.start_msg();
    pipeMac.write(buffer.begin(), encOffset);
    pipeMac.write(encryptedData.begin(), cipLen);
    pipeMac.write(pkcs7Padding.begin(), paddingSize);
    pipeMac.end_msg();

    // Read MAC on encrypted data from the pipe
    size_t macLen = pipeMac.read(macBuffer.begin(), 16);

#ifdef EB_DEBUG
    DEBUG_MSGF((TAG"MAC message len: %lu, padding length: %lu:, totalWithMac: %lu", macLen, paddingSize, encOffset+cipLen+macLen+paddingSize));
#endif

    int offset = 0;
    dest.resize(encOffset+cipLen+macLen+paddingSize);
    memcpy(dest.begin(),           buffer.begin(),        encOffset);    offset+=encOffset;
    memcpy(dest.begin()+offset,    encryptedData.begin(), cipLen);       offset+=cipLen;
    memcpy(dest.begin()+offset,    pkcs7Padding.begin(),  paddingSize);  offset+=paddingSize;
    memcpy(dest.begin()+offset,    macBuffer.begin(),     macLen);
    return 0;
}


Json::Value ShsmCreateUO::getBestImportKey(const Json::Value & importKeys){
    Json::Value kRsa2048(0);
    Json::Value kRsa1024(0);

    for(unsigned int idx = 0, len = importKeys.size(); idx < len; ++idx){
        const Json::Value cKey = importKeys[idx];
        if (cKey.isNull() || cKey["type"].isNull()){
            continue;
        }

        if (!kRsa1024.isNull() && cKey["type"].asString() == "rsa1024"){
            kRsa1024 = cKey;
        }
        if (!kRsa2048.isNull() && cKey["type"].asString() == "rsa2048"){
            kRsa2048 = cKey;
        }
    }

    return kRsa2048.isNull() ? kRsa1024 : kRsa2048;
}

int ShsmCreateUO::encryptRSA(const Json::Value & rsaKey, BotanSecureByteVector & buffer, BotanSecureByteVector & dest){
    int res = -1;
    Botan::RSA_PublicKey * tmpPub = ShsmCreateUO::readSerializedRSAPubKey(rsaKey, &res);
    if (res != 0 || tmpPub == nullptr){
        ERROR_MSGF((TAG"RSA pub key deserialization failed: %d", res));
        return -1;
    }

    std::unique_ptr<Botan::RSA_PublicKey> pubKey(tmpPub);
    Botan::PK_Encryptor_EME encryptor(*tmpPub, "EME-PKCS1-v1_5");

    // Do the encryption with padding.
    dest = encryptor.encrypt(buffer.begin(), buffer.size(), ShsmApiUtils::rng());
    return 0;
}

Botan::RSA_PublicKey * ShsmCreateUO::readSerializedRSAPubKey(const Json::Value & rsaKey, int * status){
    if (rsaKey.isNull() || rsaKey["key"].isNull()){
        if (status) *status = -1;
        return nullptr;
    }

    return ShsmCreateUO::readSerializedRSAPubKey(rsaKey["key"].asString(), status);
}

Botan::RSA_PublicKey * ShsmCreateUO::readSerializedRSAPubKey(const std::string & rsaKey, int * status){
    // Convert hexadecimal to byte array.
    // TAG|len-2B|value. 81 = exponent, 82 = modulus
    BotanSecureByteVector rsaBuff;
    int res = ShsmCreateUO::parseHexToVector(rsaKey, rsaBuff);
    if (res != 0){
        if (status) *status = -9;
        return nullptr;
    }

    bool nOk = false, eOk = false;
    Botan::BigInt n;
    Botan::BigInt e;

    Botan::byte * rsa = rsaBuff.begin();
    unsigned tag, len, pos = 0, ln = (unsigned)rsaBuff.size();
    for(;pos < ln;){
        tag = rsa[pos]; pos += 1;
        len = (unsigned)ShsmApiUtils::getInt16FromBuff(rsa+pos); pos += 2;
        switch(tag){
            case 0x81:
                eOk = true;
                e.binary_decode(rsa+pos, len);
                break;
            case 0x82:
                nOk = true;
                n.binary_decode(rsa+pos, len);
                break;
            default:
                break;
        }
        pos += len;
    }

    if (!nOk || !eOk){
        if (status) *status = -10;
        return nullptr;
    }

    if (status) *status = 0;
    return new Botan::RSA_PublicKey(n, e);
}

int ShsmCreateUO::parseHexToVector(std::string hex, BotanSecureByteVector &vector) {
    size_t len = (size_t)ShsmApiUtils::getJsonByteArraySize(hex);
    if (len <= 0){
        ERROR_MSGF((TAG"Hex format invalid"));
        return 1;
    }

    vector.resize(len);
    size_t realSize = ShsmApiUtils::hexToBytes(hex, vector.begin(), (size_t) len);
    vector.resize(realSize);
    return 0;
}

Json::Value ShsmCreateUO::importObject(SoftSlot *slot, ShsmImportRequest *req, int * status) {
    size_t tplSize = req->getTplPrepared().size();
    const Botan::byte * tplHex = req->getTplPrepared().begin();
    std::string tplHexString = ShsmApiUtils::bytesToHex(tplHex, tplSize);

    Json::Value data;
    data["objectid"] = req->getObjectId();
    data["importkey"] = req->getImportKey()["id"];
    data["object"] = tplHexString;
    data["authorization"] = req->getAuthorization();

    // Request body
    Json::Value jReq;
    jReq["function"] = "CreateUserObject";
    jReq["version"] = "1.0";
    jReq["objectid"] = ShsmApiUtils::generateApiObjectId(slot->apiKey, 0x1);
    jReq["nonce"] = ShsmApiUtils::generateNonce(16);
    jReq["data"] = data;

    // Do the request with retry. isNull() == true in case of a fail.
    Json::Value resp = ShsmUtils::requestWithRetry(slot->getRetry(), slot->host.c_str(), slot->getEnrollPort(), jReq, status);
    return resp;
}

ShsmUserObjectInfo *
ShsmCreateUO::buildImportedObject(SoftSlot *slot, ShsmImportRequest *req, const Json::Value &importResp, int * status) {
    if (importResp.isNull()
        || importResp["result"].isNull()
        || importResp["result"]["handle"].isNull())
    {
        ERROR_MSGF((TAG"Import result is invalid %s", ShsmApiUtils::json2string(importResp).c_str()));
        if (status) *status = -1;
        return nullptr;
    }

    // TEST_API00000022480000300004
    std::string handleStr = importResp["result"]["handle"].asString();
    unsigned long hndSize = handleStr.size();

    std::string apiKey = handleStr.substr(0, hndSize-10-10);
    std::string uoIdStr = handleStr.substr(hndSize-10-10+2, 8);
    std::string uoTypeStr = handleStr.substr(hndSize-10+2, 8);

    unsigned long uoId = ShsmApiUtils::getInt32FromHexString(uoIdStr.c_str());
    unsigned long uoType = ShsmApiUtils::getInt32FromHexString(uoTypeStr.c_str());

    ShsmUserObjectInfo * uo = new ShsmUserObjectInfo();
    uo->setKeyId(uoId);
    uo->setKeyType(uoType);

    uo->setEncKey(std::make_shared<BotanSecureByteKey>(req->getCommEncKey()));
    uo->setMacKey(std::make_shared<BotanSecureByteKey>(req->getCommMacKey()));

    // Store API key only if it differs from slot.
    if (slot == nullptr || slot->getApiKey() != apiKey){
        uo->setApiKey(std::make_shared<std::string>(apiKey));
    }

    // Set default slot reference, if no hostname is defined, implementation will use slot's ones.
    uo->setSlot(slot);

    if (status) *status = 0;
    return uo;
}

ShsmPrivateKey *
ShsmCreateUO::buildImportedPrivateKey(SoftSlot *slot,
                                      ShsmImportRequest *req,
                                      const Json::Value &importResp,
                                      int *status)
{
    if (importResp.isNull()
        || importResp["result"].isNull()
        || importResp["result"]["handle"].isNull()
        || importResp["result"]["publickey"].isNull()) // we know we create RSA key
    {
        ERROR_MSGF((TAG"Import result is invalid %s", ShsmApiUtils::json2string(importResp).c_str()));
        if (status) *status = -1;
        return nullptr;
    }

    // Process public key part from the response.
    int res = 0;
    std::string pubKeyStr = importResp["result"]["publickey"].asString();
    Botan::RSA_PublicKey * pubKey = ShsmCreateUO::readSerializedRSAPubKey(pubKeyStr, &res);
    std::unique_ptr<Botan::RSA_PublicKey> pubKeyUniquePtr(pubKey); // to release it after going out of scope

    if (pubKey == nullptr || res != 0){
        DEBUG_MSGF((TAG"Error: in parsing public key [%s]", pubKeyStr.c_str()));
        if (status) *status = -1;
        return nullptr;
    }

    res = 0;
    ShsmUserObjectInfo * uo = ShsmCreateUO::buildImportedObject(slot, req, importResp, &res);
    if (uo == nullptr || res != 0){
        DEBUG_MSGF((TAG"Error: in building UO [%d]", res));
        if (status) *status = -2;
        return nullptr;
    }

    ShsmPrivateKey * key = new ShsmPrivateKey(pubKey->get_n(), pubKey->get_e(), std::shared_ptr<ShsmUserObjectInfo>(uo));
    return key;
}

ShsmPrivateKey *ShsmCreateUO::createNewRsaKey(SoftSlot *slot, Json::Value *extraSpec, int bitSize, int *status) {
    // Create template specifications, using local config and defaults.
    int res = 0;
    Json::Value tplSpec = extraSpec != nullptr && !extraSpec->isNull() ?
                          ShsmCreateUO::getTemplateRequestSpec(extraSpec) :
                          ShsmCreateUO::getTemplateRequestSpec(slot);

    // Set type of object we are interested in - RSA with given bits.
    if (ShsmCreateUO::setRsaType(&tplSpec, bitSize) != 0){
        DEBUG_MSGF(("C_GenerateKeyPair: Unsupported RSA modulus bit size: %d", bitSize));
        if (status) *status = -1;
        return nullptr;
    }

    // Fetch template for new UO.
    Json::Value tplResp = ShsmCreateUO::templateRequest(slot, &tplSpec, &res);
    if (tplResp.isNull() || res != 0){
        DEBUG_MSGF(("C_GenerateKeyPair: Could not fetch template, code: %d", res));
        if (status) *status = -2;
        return nullptr;
    }

    // Process the template, fill in the keys, do the crypto
    std::unique_ptr<ShsmImportRequest> importReq(ShsmCreateUO::processTemplate(slot, &tplSpec, &tplResp, &res));
    if (res != 0 || !importReq){
        DEBUG_MSGF(("C_GenerateKeyPair: Could not process the template, code: %d", res));
        if (status) *status = -3;
        return nullptr;
    }

    // Import the initialized UO
    Json::Value importResp = ShsmCreateUO::importObject(slot, importReq.get(), &res);
    if (importResp.isNull() || res != 0){
        DEBUG_MSGF(("C_GenerateKeyPair: Import failed, code: %d", res));
        if (status) *status = -4;
        return nullptr;
    }

    // Build ShsmPrivateKey from the import result.
    std::unique_ptr<ShsmPrivateKey> privKey(ShsmCreateUO::buildImportedPrivateKey(slot, importReq.get(), importResp, &res));
    if (res != 0 || !privKey){
        DEBUG_MSGF(("C_GenerateKeyPair: Could not import the key, code: %d", res));
        if (status) *status = -5;
        return nullptr;
    }

    ShsmPrivateKey * keyToReturn = privKey.get();
    privKey.release();
    return keyToReturn;
}

