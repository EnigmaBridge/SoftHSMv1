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
#include <json.h>
#include <botan/block_cipher.h>
#include <botan/symkey.h>
#include <botan/b64_filt.h>
#include <botan/engine.h>
#include <botan/lookup.h>

CK_BBOOL ShsmUtils::isShsmKey(SoftDatabase *db, CK_OBJECT_HANDLE hKey) {
    return db->getBooleanAttribute(hKey, CKA_SHSM_KEY, CK_FALSE);
}

SHSM_KEY_HANDLE ShsmUtils::getShsmKeyHandle(SoftDatabase *db, CK_OBJECT_HANDLE hKey) {
    SHSM_KEY_HANDLE shsmHandle = SHSM_INVALID_KEY_HANDLE;

    // Load this attribute via generic DB access call.
    CK_ATTRIBUTE attr = {CKA_SHSM_KEY_HANDLE, (void *) &shsmHandle, sizeof(SHSM_KEY_HANDLE)};
    CK_RV shsmRet = db->getAttribute(hKey, &attr);

    if (shsmRet != CKR_OK){
        ERROR_MSG("getShsmKeyHandle", "Could not get attribute SHSM_KEY_HANDLE");
        return SHSM_INVALID_KEY_HANDLE;
    }

    return shsmHandle;
}

std::string ShsmUtils::getRequestDecrypt(ShsmPrivateKey *privKey, std::string key, const Botan::byte byte[], size_t t, std::string nonce) {
    // Generate JSON request here.
    Json::Value jReq;
    jReq["function"] = "ProcessData";
    jReq["version"] = "1.0";
    jReq["nonce"] = !nonce.empty() ? nonce : ShsmApiUtils::generateNonce(16);
    const int keyId = (int) privKey->getKeyId();

    // Object id, long to string.
    char buf[16] = {0};
    snprintf(buf, 16, "%d", keyId);
    jReq["objectid"] = buf;

    std::ostringstream dataBuilder;
    dataBuilder << "Packet0_RSA2048_0000";

    // AES-256-CBC encrypt data for decryption.
    // IV is null for now, TODO: force others to change this to AES-GCM with correct IV.
    Botan::byte iv[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    Botan::byte encKey[32];
    size_t keySize = ShsmApiUtils::hexToBytes(key, encKey, 32);
    Botan::SecureVector<Botan::byte> tSecVector(encKey, 32);
    if (keySize != 32){
        ERROR_MSG("getRequestDecrypt", "AES key size is invalid");
    }

    Botan::SymmetricKey aesKey(tSecVector);
    Botan::InitializationVector aesIv(iv, 16);

    // Encryption & Encode
    Botan::Pipe pipe(Botan::get_cipher("AES-256/CBC/PKCS7", aesKey, aesIv, Botan::ENCRYPTION));
    pipe.start_msg();

    std::string toDecryptStr = ShsmApiUtils::bytesToHex(byte, t);
    DEBUG_MSGF(("To decode req: [%s]", toDecryptStr.c_str()));

    // Write header of form 0x1f | <UOID-4B>
    Botan::byte dataHeader[5] = {0x1f, 0x0, 0x0, 0x0, 0x0};
    ShsmApiUtils::writeLongToBuff((unsigned long)keyId, dataHeader + 1);
    pipe.write(dataHeader, 5);
    pipe.write(byte, t);
    pipe.end_msg();

    DEBUG_MSGF(("%x %x %x %x %x key: %lu", dataHeader[0], dataHeader[1], dataHeader[2], dataHeader[3], dataHeader[4], (unsigned long)keyId));

    // Read the output.
    Botan::byte * buff = (Botan::byte *) malloc(sizeof(Botan::byte) * (t + 64));
    if (buff == NULL_PTR){
        ERROR_MSG("getRequestDecrypt", "Could not allocate enough memory for encryption operation");
        return "";
    }

    size_t cipLen = pipe.read(buff, (t + 64));

    // Add hex-encoded input data here.
    dataBuilder << ShsmApiUtils::bytesToHex(buff, cipLen);

    // Deallocate temporary buffer.
    free(buff);

    // ProcessData - add data part.
    jReq["data"] = dataBuilder.str();

    // Build string request body.
    Json::FastWriter jWriter;
    std::string json = jWriter.write(jReq) + "\n"; // EOL at the end of the request.
    return json;
}

Botan::SecureVector<Botan::byte> ShsmUtils::readProtectedData(Botan::byte * buff, size_t size, std::string key, int * status) {
    // AES-256-CBC encrypt data for decryption.
    // IV is null for now, TODO: force others to change this to AES-GCM with correct IV.
    Botan::byte iv[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    Botan::byte encKey[32];
    size_t keySize = ShsmApiUtils::hexToBytes(key, encKey, 32);
    Botan::SecureVector<Botan::byte> tSecVector(encKey, 32);
    if (keySize != 32){
        ERROR_MSG("getRequestDecrypt", "AES key size is invalid");
    }

    Botan::SymmetricKey aesKey(tSecVector);
    Botan::InitializationVector aesIv(iv, 16);

    // Decryption.
    Botan::Pipe pipe(Botan::get_cipher("AES-256/CBC/PKCS7", aesKey, aesIv, Botan::DECRYPTION));
    pipe.process_msg(buff, size);

    // Read the output.
    Botan::byte * outBuff = (Botan::byte *) malloc(sizeof(Botan::byte) * (size + 64));
    if (buff == NULL_PTR){
        ERROR_MSG("readProtectedData", "Could not allocate enough memory for decryption operation");
        *status = -1;
        return Botan::SecureVector<Botan::byte>(0);
    }

    // Write header of form 0x1f | <UOID-4B>
    size_t cipLen = pipe.read(outBuff, (size + 64));
    if (cipLen < 5){
        ERROR_MSG("readProtectedData", "Decryption failed, size is too small");
        *status = -2;
        free(outBuff);
        return Botan::SecureVector<Botan::byte>(0);
    }

    DEBUG_MSGF(("After decryption: cipLen=%lu, %x %x %x %x %x %x %x", cipLen,
               outBuff[0],
               outBuff[1],
               outBuff[2],
               outBuff[3],
               outBuff[4],
               outBuff[5],
               outBuff[6]
               ));

    // Prepare return object from the processed buffer.
    Botan::SecureVector<Botan::byte> toReturn = Botan::SecureVector<Botan::byte>(outBuff + 5, cipLen - 5);

    // Deallocate temporary buffer.
    free(outBuff);

    *status = 0;
    return toReturn;
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
    DEBUG_MSGF(("RAW data: %x %x %x %x %x %x %x",
               buff[0],
               buff[1],
               buff[2],
               buff[3],
               buff[4],
               buff[5],
               buff[6]
               ));
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
