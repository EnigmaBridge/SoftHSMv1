//
// Created by Dusan Klinec on 21.06.15.
//

#include "ShsmUtils.h"
#include "log.h"
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <iomanip>
#include <string>
#include <iomanip>
#include <iostream>     // std::cout
#include <sstream>      // std::ostringstream
#include "ShsmApiUtils.h"
#include "ShsmProcessDataRequestBuilder.h"
#include "ShsmEngine.h"
#include <json.h>
#include <botan/block_cipher.h>
#include <botan/symkey.h>
#include <botan/b64_filt.h>
#include <botan/engine.h>
#include <botan/lookup.h>
#define TAG "ShsmUtils: "
#define MACTAGLEN 16

CK_BBOOL ShsmUtils::isShsmKey(SoftDatabase *db, CK_OBJECT_HANDLE hKey) {
    return db->getBooleanAttribute(hKey, CKA_SHSM_KEY, CK_FALSE);
}

int ShsmUtils::getShsmKeyHandle(SoftDatabase *db, CK_OBJECT_HANDLE hKey, SHSM_KEY_HANDLE * kHnd, SHSM_KEY_TYPE * kType) {
    if (kHnd != NULL) {
        SHSM_KEY_HANDLE shsmHandle = SHSM_INVALID_KEY_HANDLE;

        // Load this attribute via generic DB access call.
        CK_ATTRIBUTE attr = {CKA_SHSM_UO_HANDLE, (void *) &shsmHandle, sizeof(SHSM_KEY_HANDLE)};
        CK_RV shsmRet = db->getAttribute(hKey, &attr);

        if (shsmRet != CKR_OK) {
            ERROR_MSG("getShsmKeyHandle", "Could not get attribute SHSM_KEY_HANDLE");
            return -1;
        }
        *kHnd = shsmRet;
    }

    if (kType != NULL) {
        SHSM_KEY_TYPE shsmType = SHSM_INVALID_KEY_TYPE;

        // Load this attribute via generic DB access call.
        CK_ATTRIBUTE attr = {CKA_SHSM_UO_TYPE, (void *) &shsmType, sizeof(SHSM_KEY_TYPE)};
        CK_RV shsmRet = db->getAttribute(hKey, &attr);

        if (shsmRet != CKR_OK) {
            ERROR_MSG("getShsmKeyHandle", "Could not get attribute CKA_SHSM_UO_TYPE");
            return -1;
        }
        *kType = shsmRet;
    }

    return 0;
}

std::shared_ptr<ShsmUserObjectInfo> ShsmUtils::buildShsmUserObjectInfo(SoftDatabase *db, CK_OBJECT_HANDLE hKey, SoftSlot * slot) {
    std::shared_ptr<ShsmUserObjectInfo> uo(new ShsmUserObjectInfo());
    CK_ATTRIBUTE attr;
    CK_RV shsmRet;

    SHSM_KEY_HANDLE shsmHandle = SHSM_INVALID_KEY_HANDLE;
    SHSM_KEY_TYPE shsmType = SHSM_INVALID_KEY_TYPE;

    int res = ShsmUtils::getShsmKeyHandle(db, hKey, &shsmHandle, &shsmType);
    if (res != 0){
        ERROR_MSG("buildShsmUserObjectInfo", "Could not get attribute SHSM_KEY_HANDLE");
        return nullptr;
    }

    uo->setKeyId(shsmHandle);
    uo->setKeyType(shsmType);

#define EB_COM_KEY_SIZE 32
#define EB_API_KEY_SIZE 256
#define EB_HOSTNAME_SIZE 256

    // encKey & macKey, apiKey, hostname, portnumber buffers.
    Botan::byte encKeyBuff[EB_COM_KEY_SIZE];
    Botan::byte macKeyBuff[EB_COM_KEY_SIZE];
    char apiKeyBuff[EB_API_KEY_SIZE];
    char hostnameBuff[EB_HOSTNAME_SIZE];
    int portNumBuff = -1;
    bool hasHostname = false;

    // EncKey, mandatory.
    attr = {CKA_SHSM_UO_ENCKEY, (void *) &encKeyBuff, EB_COM_KEY_SIZE};
    shsmRet = db->getAttribute(hKey, &attr);
    if (shsmRet != CKR_OK || attr.ulValueLen != EB_COM_KEY_SIZE){
        ERROR_MSG("buildShsmUserObjectInfo", "Could not get attribute CKA_SHSM_UO_ENCKEY");
        return nullptr;
    } //Botan::SecureVector<Botan::byte>
    uo->setEncKey(std::make_shared<BotanSecureByteKey>(encKeyBuff, (size_t)EB_COM_KEY_SIZE));

    // MacKey, mandatory.
    attr = {CKA_SHSM_UO_MACKEY, (void *) &macKeyBuff, EB_COM_KEY_SIZE};
    shsmRet = db->getAttribute(hKey, &attr);
    if (shsmRet != CKR_OK || attr.ulValueLen != EB_COM_KEY_SIZE){
        ERROR_MSG("buildShsmUserObjectInfo", "Could not get attribute CKA_SHSM_UO_MACKEY");
        return nullptr;
    }
    uo->setMacKey(std::make_shared<BotanSecureByteKey>(macKeyBuff, (size_t)EB_COM_KEY_SIZE));

    // ApiKey [optional]
    attr = {CKA_SHSM_UO_APIKEY, (void *) &apiKeyBuff, EB_API_KEY_SIZE};
    shsmRet = db->getAttribute(hKey, &attr);
    if (shsmRet == CKR_OK){
        if (attr.ulValueLen >= EB_API_KEY_SIZE){
            ERROR_MSG("buildShsmUserObjectInfo", "ApiKey too big");
        } else {
            uo->setApiKey(std::make_shared<std::string>(reinterpret_cast<char const*>(apiKeyBuff), attr.ulValueLen));
        }
    }

    // Hostname [optional]
    attr = {CKA_SHSM_UO_HOSTNAME, (void *) &hostnameBuff, EB_HOSTNAME_SIZE};
    shsmRet = db->getAttribute(hKey, &attr);
    if (shsmRet == CKR_OK){
        if (attr.ulValueLen >= EB_HOSTNAME_SIZE){
            ERROR_MSG("buildShsmUserObjectInfo", "Hostname too big");
        } else {
            uo->setHostname(std::make_shared<std::string>(reinterpret_cast<char const*>(hostnameBuff), attr.ulValueLen));
            hasHostname = true;
        }
    }

    // If hostname, try port [optional]
    if (hasHostname){
        attr = {CKA_SHSM_UO_PORT, (void *) &portNumBuff, sizeof(int)};
        shsmRet = db->getAttribute(hKey, &attr);
        if (shsmRet == CKR_OK){
            uo->setPort(portNumBuff);
        }
    }

    // Set default slot reference, if no hostname is defined, implementation will use slot's ones.
    uo->setSlot(slot);

//    // Copy from general configuration.
//    if (slot != NULL && !uo->getApiKey()){
//        std::string apiKey = slot->getApiKey();
//        uo->setApiKey(std::make_shared<std::string>(apiKey));
//    }
//
//    if (slot != NULL && !uo->getHostname()){
//        std::string hostname = slot->getHost();
//        uo->setHostname(std::make_shared<std::string>(hostname));
//        if (uo->getPort() <= 0){
//            uo->setPort(slot->getPort());
//        }
//    }

    return uo;
}

std::string ShsmUtils::getRequestDecrypt(const ShsmPrivateKey *privKey, const Botan::byte byte[], size_t t) {
    const std::shared_ptr<ShsmUserObjectInfo> uo = privKey->getUo();
    if (!uo){
        ERROR_MSG("getRequestDecrypt", "Empty UO");
        return "";
    }

    int statusCode = -1;
    t_eb_request_type reqType = privKey->get_n().bits() <= 1024 ? EB_REQUEST_RSA1024 : EB_REQUEST_RSA2048;
    ShsmProcessDataRequest * req = ShsmProcessDataRequestBuilder::buildProcessDataRequest(byte, t, uo.get(), reqType, NULL, 0, &statusCode);
    if (req == nullptr || statusCode != 0){
        ERROR_MSG("getRequestDecrypt", "Cannot generate requets");
        return "";
    }

    std::string reqBody = req->getRequest();
    delete req;

    return reqBody;
}

int ShsmUtils::readProtectedData(Botan::byte * buff, size_t size,
                                 BotanSecureByteKey key, BotanSecureByteKey macKey,
                                 Botan::SecureVector<Botan::byte> ** result,
                                 Botan::byte * nonceBuff,
                                 SHSM_KEY_HANDLE * responseUOID)
{
#define NONCEOFFSET 5

    // AES-256-CBC encrypt data for decryption.
    // IV is null for now, but freshness nonce in the first block imitates IV into some extent.
    const Botan::byte iv[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    if (key.size() != 32 || macKey.size() != 32){
        ERROR_MSG("getRequestDecrypt", "AES (enc or mac) key size is invalid");
        return EB_PROCESSDATA_UNWRAP_STATUS_INVALID_KEYS;
    }

    const Botan::SymmetricKey aesKey(key);
    const Botan::SymmetricKey aesMacKey(macKey);
    const Botan::InitializationVector aesIv(iv, 16);

    // Check size, MAC tag is at the end of the message.
    if (size < (16+MACTAGLEN)){
        ERROR_MSG("readProtectedData", "Input data too short");
        return EB_PROCESSDATA_UNWRAP_STATUS_DATA_TOO_SHORT;
    }

    // Get the MAC tag from the message.
    const Botan::byte * givenMac = buff+(size-MACTAGLEN);

    // Decryption + MAC computation.
    // Ciphertext is forked to decryption routine and to HMAC computation routine.
    Botan::Pipe pipe(
            new Botan::Fork(
                    // output from decryption goes here, messageId=0
                    Botan::get_cipher("AES-256/CBC/PKCS7", aesKey, aesIv, Botan::DECRYPTION),
                    // output of MAC goes here, messageId=1.
                    new Botan::MAC_Filter("CBC_MAC(AES-256)", aesMacKey)
            )
    );

    pipe.process_msg(buff, size-MACTAGLEN);

    // Read the MAC.
    Botan::byte computedMac[MACTAGLEN];
    size_t computedMacSize = pipe.read(computedMac, MACTAGLEN, 1);
    if (computedMacSize != MACTAGLEN){
        ERROR_MSG("readProtectedData", "Computed MAC tag is invalid");
        return EB_PROCESSDATA_UNWRAP_STATUS_MALFORMED;
    }

    // Compare the MAC.
    if (memcmp(givenMac, computedMac, MACTAGLEN) != 0){
        ERROR_MSG("readProtectedData", "MAC invalid");
        return EB_PROCESSDATA_UNWRAP_STATUS_HMAC_INVALID;
    }

    // Read the output.
    Botan::byte * outBuff = (Botan::byte *) malloc(sizeof(Botan::byte) * (size + 64));
    if (buff == NULL_PTR){
        ERROR_MSG("readProtectedData", "Could not allocate enough memory for decryption operation");
        return EB_PROCESSDATA_UNWRAP_STATUS_GENERAL_ERROR;
    }

    // Read header of form 0xf1 | <UOID-4B> | <mangled-freshness-nonce-8B>
    size_t cipLen = pipe.read(outBuff, (size + 64), 0);
    if (cipLen < NONCEOFFSET + SHSM_FRESHNESS_NONCE_LEN){
        ERROR_MSG("readProtectedData", "Decryption failed, size is too small");
        free(outBuff);
        return EB_PROCESSDATA_UNWRAP_STATUS_DECRYPTION_ERROR;
    }

    // Check the flag, has to be 0xf1
    if (outBuff[0] != 'f' || outBuff[1] != '1'){
        ERROR_MSG("readProtectedData", "Invalid message block format");
        free(outBuff);
        return EB_PROCESSDATA_UNWRAP_STATUS_UNEXPECTED_FORMAT;
    }

    // Read user object ID from he buffer.
    SHSM_KEY_HANDLE userObjectId = (SHSM_KEY_HANDLE) ShsmApiUtils::getInt32FromHexString((const char *) outBuff + 1);
    if (responseUOID != NULL){
        *responseUOID = userObjectId;
    }

    // Demangle nonce in the buffer.
    ShsmUtils::demangleNonce(outBuff+NONCEOFFSET, SHSM_FRESHNESS_NONCE_LEN);
    if (nonceBuff != NULL){
        memcpy(nonceBuff, outBuff+NONCEOFFSET, SHSM_FRESHNESS_NONCE_LEN);
    }

#ifdef EB_DEBUG
    DEBUG_MSGF((TAG"After decryption: cipLen=%lu, UOid: %04X, nonce %02x%02x%02x%02x%02x%02x%02x%02x", cipLen, userObjectId,
               outBuff[NONCEOFFSET+0], outBuff[NONCEOFFSET+1],
               outBuff[NONCEOFFSET+2], outBuff[NONCEOFFSET+3],
               outBuff[NONCEOFFSET+4], outBuff[NONCEOFFSET+5],
               outBuff[NONCEOFFSET+6], outBuff[NONCEOFFSET+7]
               ));
#endif

    // Prepare return object from the processed buffer.
    *result = new Botan::SecureVector<Botan::byte>(outBuff + NONCEOFFSET + SHSM_FRESHNESS_NONCE_LEN,
                                                   cipLen - NONCEOFFSET - SHSM_FRESHNESS_NONCE_LEN);
    // Deallocate temporary buffer used for unwrapping ProcessData response.
    free(outBuff);

    return EB_PROCESSDATA_UNWRAP_STATUS_SUCCESS;
}

ssize_t ShsmUtils::removePkcs15Padding(const Botan::byte *buff, size_t len, Botan::byte *out, size_t maxLen, int *status) {
    // EB = 00 || BT || PS || 00 || D
    //  .. EB = encryption block
    //  .. BT = 1B block type {00, 01} for private key operation, {02} for public key operation.
    //  .. PS = padding string. Has length k - 3 - len(D).
    //          if BT == 0, then padding consists of 0x0, but we need to know size of data in order to remove padding unambiguously.
    //          if BT == 1, then padding consists of 0xFF.
    //          if BT == 2, then padding consists of randomly generated bytes, does not contain 0x00 byte.
    //
    // [https://tools.ietf.org/html/rfc2313 PKCS#1 1.5]
    if (len < 3){
        ERROR_MSG("removePkcs15Padding", "Data is too short");
        *status = -1;
        return -1;
    }

    // Check the first byte.
    if (buff[0] != (Botan::byte)0x0){
        ERROR_MSG("removePkcs15Padding", "Padding data error, prefix is not 00");
        *status = -2;
        return -2;
    }

    // BT can be only from set {0,1,2}.
    const unsigned char bt = buff[1];
    if (bt != 0 && bt != 1 && bt != 2){
        ERROR_MSG("removePkcs15Padding", "Padding data error, BT is outside of the definition set");
        *status = -3;
        return -3;
    }

    // Find D in the padded data. Strategy depends on the BT.
    ssize_t dataPosStart = -1;
    if (bt == 0){
        // Scan for first non-null character.
        for(size_t i = 2; i < len; i++){
            if (buff[i] != 0){
                dataPosStart = i;
                break;
            }
        }

    } else if (bt == 1){
        // Find 0x0, report failure in 0xff
        bool ffCorrect = true;
        for(size_t i = 2; i < len; i++){
            if (buff[i] != 0 && buff[i] != 0xff) {
                ffCorrect = false;
            }

            if (buff[i] == 0){
                dataPosStart = i+1;
                break;
            }
        }

        if (!ffCorrect){
            ERROR_MSG("removePkcs15Padding", "Trail of 0xFF in padding contains also unexpected characters");
        }

    } else {
        // bt == 2, find 0x0.
        for(size_t i = 2; i < len; i++){
            if (buff[i] == 0){
                dataPosStart = i+1;
                break;
            }
        }
    }

    // If data position is out of scope, return nothing.
    if (dataPosStart < 0 || (size_t)dataPosStart > len){
        ERROR_MSG("removePkcs15Padding", "Padding could not be parsed");
        *status = -4;
        return -4;
    }

    // Check size of the output buffer.
    const size_t dataLen = len - dataPosStart;
    if (dataLen > maxLen){
        ERROR_MSG("removePkcs15Padding", "Output buffer is too small");
        *status = -5;
        return -5;
    }

    // Copy data from input buffer to output buffer. Do it in a way that in==out, so in-place, non-destructive.
    for(size_t i = 0; i<dataLen; i++){
        out[i] = buff[dataPosStart + i];
    }

    *status = 0;
    return dataLen;
}

void ShsmUtils::demangleNonce(Botan::byte *buff, size_t len) {
    size_t idx;
    for(idx = 0; idx < len; idx++){
        buff[idx] -= 0x1;
    }
}

std::string ShsmUtils::buildApiObjectId(ShsmUserObjectInfo * uo){
    if (uo->getKeyType() != SHSM_INVALID_KEY_TYPE){
        return ShsmApiUtils::generateApiObjectId(*(uo->getApiKey()), uo->getKeyId(), uo->getKeyType());
    } else {
        return ShsmApiUtils::generateApiObjectId(*(uo->getApiKey()), uo->getKeyId());
    }
}

void ShsmUtils::addShsmEngine2Botan() {
    Botan::Algorithm_Factory& af = Botan::Global_State_Management::global_state().algorithm_factory();
    ShsmEngine * engine = new ShsmEngine;

    af.add_engine(engine);
    af.set_preferred_provider("RSA", engine->provider_name());
    af.set_preferred_provider("RSA/Raw", engine->provider_name());
    af.set_preferred_provider("RSA/PKCS1-1.5", engine->provider_name());
}
