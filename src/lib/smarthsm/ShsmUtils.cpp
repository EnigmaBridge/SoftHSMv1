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

SHSM_KEY_HANDLE ShsmUtils::getShsmKeyHandle(SoftDatabase *db, CK_OBJECT_HANDLE hKey) {
    SHSM_KEY_HANDLE shsmHandle = SHSM_INVALID_KEY_HANDLE;

    // Load this attribute via generic DB access call.
    CK_ATTRIBUTE attr = {CKA_SHSM_UO_HANDLE, (void *) &shsmHandle, sizeof(SHSM_KEY_HANDLE)};
    CK_RV shsmRet = db->getAttribute(hKey, &attr);

    if (shsmRet != CKR_OK){
        ERROR_MSG("getShsmKeyHandle", "Could not get attribute SHSM_KEY_HANDLE");
        return SHSM_INVALID_KEY_HANDLE;
    }

    return shsmHandle;
}

std::shared_ptr<ShsmUserObjectInfo> ShsmUtils::buildShsmUserObjectInfo(SoftDatabase *db, CK_OBJECT_HANDLE hKey, SoftSlot * slot) {
    std::shared_ptr<ShsmUserObjectInfo> uo(new ShsmUserObjectInfo());
    SHSM_KEY_HANDLE shsmHandle = SHSM_INVALID_KEY_HANDLE;

    // Load this attribute via generic DB access call.
    CK_ATTRIBUTE attr = {CKA_SHSM_UO_HANDLE, (void *) &shsmHandle, sizeof(SHSM_KEY_HANDLE)};
    CK_RV shsmRet = db->getAttribute(hKey, &attr);
    if (shsmRet != CKR_OK){
        ERROR_MSG("buildShsmUserObjectInfo", "Could not get attribute SHSM_KEY_HANDLE");
        return nullptr;
    }
    uo->setKeyId(shsmHandle);

#define EB_COM_KEY_SIZE 32
#define EB_API_KEY_SIZE 64
#define EB_HOSTNAME_SIZE 256

    // encKey & macKey, apiKey, hostname, portnumber buffers.
    Botan::byte * encKeyBuff[EB_COM_KEY_SIZE];
    Botan::byte * macKeyBuff[EB_COM_KEY_SIZE];
    char * apiKeyBuff[EB_API_KEY_SIZE];
    char * hostnameBuff[EB_HOSTNAME_SIZE];
    int portNumBuff = -1;
    bool hasHostname = false;

    // EncKey, mandatory.
    attr = {CKA_SHSM_UO_ENCKEY, (void *) &encKeyBuff, EB_COM_KEY_SIZE};
    shsmRet = db->getAttribute(hKey, &attr);
    if (shsmRet != CKR_OK || attr.ulValueLen != EB_COM_KEY_SIZE){
        ERROR_MSG("buildShsmUserObjectInfo", "Could not get attribute CKA_SHSM_UO_ENCKEY");
        return nullptr;
    }
    uo->setEncKey(std::make_shared<BotanSecureByteKey>(new BotanSecureByteKey(encKeyBuff, EB_COM_KEY_SIZE)));

    // MacKey, mandatory.
    attr = {CKA_SHSM_UO_MACKEY, (void *) &macKeyBuff, EB_COM_KEY_SIZE};
    shsmRet = db->getAttribute(hKey, &attr);
    if (shsmRet != CKR_OK || attr.ulValueLen != EB_COM_KEY_SIZE){
        ERROR_MSG("buildShsmUserObjectInfo", "Could not get attribute CKA_SHSM_UO_MACKEY");
        return nullptr;
    }
    uo->setMacKey(std::make_shared<BotanSecureByteKey>(new BotanSecureByteKey(macKeyBuff, EB_COM_KEY_SIZE)));

    // ApiKey [optional]
    attr = {CKA_SHSM_UO_APIKEY, (void *) &apiKeyBuff, EB_API_KEY_SIZE};
    shsmRet = db->getAttribute(hKey, &attr);
    if (shsmRet == CKR_OK){
        if (attr.ulValueLen >= EB_API_KEY_SIZE){
            ERROR_MSG("buildShsmUserObjectInfo", "ApiKey too big");
        } else {
            uo->setApiKey(std::make_shared<std::string>(new std::string(reinterpret_cast<char const*>(apiKeyBuff), attr.ulValueLen)));
        }
    }

    // Hostname [optional]
    attr = {CKA_SHSM_UO_HOSTNAME, (void *) &hostnameBuff, EB_HOSTNAME_SIZE};
    shsmRet = db->getAttribute(hKey, &attr);
    if (shsmRet == CKR_OK){
        if (attr.ulValueLen >= EB_HOSTNAME_SIZE){
            ERROR_MSG("buildShsmUserObjectInfo", "Hostname too big");
        } else {
            uo->setHostname(std::make_shared<std::string>(new std::string(reinterpret_cast<char const*>(hostnameBuff), attr.ulValueLen)));
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

    // Copy from general configuration.
    if (slot != NULL && !uo->getApiKey()){
        uo->setApiKey(std::make_shared<std::string>(new std::string(slot->getApiKey())));
    }

    if (slot != NULL && !uo->getHostname()){
        uo->setHostname(std::make_shared<std::string>(new std::string(slot->getHost())));
        if (uo->getPort() <= 0){
            uo->setPort(slot->getPort());
        }
    }

    return uo;
}

std::string ShsmUtils::getRequestDecrypt(ShsmPrivateKey *privKey, const Botan::byte byte[], size_t t) {
    const std::shared_ptr<ShsmUserObjectInfo> uo = privKey->getUo();
    if (!uo){
        ERROR_MSG("getRequestDecrypt", "Empty UO");
        return "";
    }

    int statusCode = -1;
    t_eb_request_type reqType = privKey->getBigN().bits() <= 1024 ? EB_REQUEST_RSA1024 : EB_REQUEST_RSA2048;
    ShsmProcessDataRequest * req = ShsmProcessDataRequestBuilder::buildProcessDataRequest(byte, t, uo.get(), reqType, NULL, 0, &statusCode);
    if (req == nullptr || statusCode != 0){
        ERROR_MSG("getRequestDecrypt", "Cannot generate requets");
        return "";
    }

    std::string reqBody = req->getRequest();
    delete req;

    return reqBody;
}

int ShsmUtils::readProtectedData(Botan::byte * buff, size_t size, BotanSecureByteKey key, BotanSecureByteKey macKey, Botan::SecureVector<Botan::byte> ** result) {
    // AES-256-CBC encrypt data for decryption.
    // IV is null for now, but freshness nonce in the first block imitates IV into some extent.
    Botan::byte iv[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    if (key.size() != 32 || macKey.size() != 32){
        ERROR_MSG("getRequestDecrypt", "AES (enc or mac) key size is invalid");
    }

    Botan::SymmetricKey aesKey(key);
    Botan::SymmetricKey aesMacKey(macKey);
    Botan::InitializationVector aesIv(iv, 16);

    // Check size, MAC tag is at the end of the message.
    if (size < (16+MACTAGLEN)){
        ERROR_MSG("readProtectedData", "Input data too short");
        return -10;
    }

    // Get the MAC tag from the message.
    Botan::byte * givenMac = buff+(size-MACTAGLEN);

    // Decryption + MAC computation.
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
        return -11;
    }

    // Compare the MAC.
    if (memcmp(givenMac, computedMac, MACTAGLEN) != 0){
        ERROR_MSG("readProtectedData", "MAC invalid");
        return -12;
    }

    // Read the output.
    Botan::byte * outBuff = (Botan::byte *) malloc(sizeof(Botan::byte) * (size + 64));
    if (buff == NULL_PTR){
        ERROR_MSG("readProtectedData", "Could not allocate enough memory for decryption operation");
        return -1;
    }

    // Read header of form 0xf1 | <UOID-4B> | <mangled-freshness-nonce-8B>
    size_t cipLen = pipe.read(outBuff, (size + 64), 0);
    if (cipLen < 5+ SHSM_FRESHNESS_NONCE_LEN){
        ERROR_MSG("readProtectedData", "Decryption failed, size is too small");
        free(outBuff);
        return -2;
    }

    // Check the flag, has to be 0xf1
    if (outBuff[0] != 'f' || outBuff[1] != '1'){
        ERROR_MSG("readProtectedData", "Invalid message block format");
        free(outBuff);
        return -15;
    }

    // Read user object ID from he buffer.
    unsigned long userObjectId = ShsmApiUtils::getInt32FromHexString((const char *) outBuff + 1);

    // Demangle nonce in the buffer.
    ShsmUtils::demangleNonce(outBuff+5, SHSM_FRESHNESS_NONCE_LEN);

    DEBUG_MSGF((TAG"After decryption: cipLen=%lu, UOid: %04X, nonce %02x%02x%02x%02x%02x%02x%02x%02x", cipLen, userObjectId,
               outBuff[5+0], outBuff[5+1],
               outBuff[5+2], outBuff[5+3],
               outBuff[5+4], outBuff[5+5],
               outBuff[5+5], outBuff[5+6]
               ));

    // Prepare return object from the processed buffer.
    *result = new Botan::SecureVector<Botan::byte>(outBuff + 5 + SHSM_FRESHNESS_NONCE_LEN, cipLen - 5 - SHSM_FRESHNESS_NONCE_LEN);
    // Deallocate temporary buffer.
    free(outBuff);

    return 0;
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


void ShsmUtils::addShsmEngine2Botan() {
    Botan::Algorithm_Factory& af = Botan::Global_State_Management::global_state().algorithm_factory();
    ShsmEngine * engine = new ShsmEngine;

    af.add_engine(engine);
    af.set_preferred_provider("RSA", engine->provider_name());
    af.set_preferred_provider("RSA/Raw", engine->provider_name());
    af.set_preferred_provider("RSA/PKCS1-1.5", engine->provider_name());
}
