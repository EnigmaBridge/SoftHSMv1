//
// Created by Dusan Klinec on 21.06.15.
//

#ifndef SOFTHSMV1_SHSMUTILS_H
#define SOFTHSMV1_SHSMUTILS_H


#include "ShsmConnectionConfig.h"
#include "ShsmPrivateKey.h"
#include "SoftDatabase.h"
#include <string>

class ShsmUtils {
public:
    /**
     * Loads SHSM key handle of the object referenced by hKey. Under this value the object is referenced on the SHSM.
     */
    static SHSM_KEY_HANDLE getShsmKeyHandle(SoftDatabase * db, CK_OBJECT_HANDLE hKey);

    /**
     * Returns true if given key is stored in SHSM.
     */
    static CK_BBOOL isShsmKey(SoftDatabase * db, CK_OBJECT_HANDLE hKey);

    /**
     * Returns request string for query for SHSM public key.
     */
    static std::string getRequestShsmPubKey(std::string nonce);

    /**
     * Returns request string for decryption query.
     */
    static std::string getRequestDecrypt(ShsmPrivateKey * privKey, std::string key, const Botan::byte byte[], size_t t, std::string nonce);

};


#endif //SOFTHSMV1_SHSMUTILS_H
