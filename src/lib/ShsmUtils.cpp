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
#include <botan/types.h>
#include <sstream>
#include <json.h>
#include <src/common/ShsmApiUtils.h>

CK_BBOOL ShsmUtils::isShsmKey(SoftDatabase *db, CK_OBJECT_HANDLE hKey) {
    return db->getBooleanAttribute(hKey, CKA_SHSM_KEY, CK_FALSE);
}

SHSM_KEY_HANDLE ShsmUtils::getShsmKeyHandle(SoftDatabase *db, CK_OBJECT_HANDLE hKey) {
    SHSM_KEY_HANDLE shsmHandle;

    // Load this attribute via generic DB access call.
    const CK_ATTRIBUTE attr = {CKA_SHSM_KEY_HANDLE, (void *) &shsmHandle, sizeof(SHSM_KEY_HANDLE)};
    CK_RV shsmRet = db->getAttribute(hKey, &attr);

    if (shsmRet != CKR_OK){
        return SHSM_INVALID_KEY_HANDLE;
    }

    return shsmHandle;
}

std::string ShsmUtils::getRequestShsmPubKey(std::string nonce) {
    // Generate JSON request here.
    Json::Value jReq;
    jReq["function"] = "GetSHSMPubKey";
    jReq["version"] = "1.0";
    jReq["nonce"] = nonce;


    // Build string request body.
    Json::Writer jWriter;
    std::string json = jWriter.write(jReq) + "\n"; // EOL at the end of the request.
    return json;
}

std::string ShsmUtils::getRequestDecrypt(ShsmPrivateKey *privKey, std::string key, const Botan::byte byte[], size_t t, std::string nonce) {
    // Generate JSON request here.
    Json::Value jReq;
    jReq["function"] = "ProcessData";
    jReq["version"] = "1.0";
    jReq["nonce"] = !nonce.empty() ? nonce : ShsmApiUtils::generateNonce(16);
    jReq["objectid"] = privKey->getKeyId();

    const std::string dataPrefix = "Packet0_RSA2048_";
    const std::stringstream dataBuilder;
    dataBuilder << dataPrefix;

    // TODO: AES-256-CBC encrypt data for decryption.

    // Add hex-encoded input data here.
    dataBuilder << ShsmApiUtils::bytesToHex(byte, t);

    // Build string request body.
    Json::Writer jWriter;
    std::string json = jWriter.write(jReq) + "\n"; // EOL at the end of the request.
    return json;
}



