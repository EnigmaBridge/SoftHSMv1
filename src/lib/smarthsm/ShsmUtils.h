//
// Created by Dusan Klinec on 21.06.15.
//

#ifndef SOFTHSMV1_SHSMUTILS_H
#define SOFTHSMV1_SHSMUTILS_H

#include "ShsmApiUtils.h"
#include "ShsmPrivateKey.h"
#include "SoftDatabase.h"
#include <string>
#include <src/lib/SoftSlot.h>

// Response codes produced by readProtectedData.
typedef enum t_ebUnwrapProcessDataResponseCode {
    EB_PROCESSDATA_UNWRAP_STATUS_INVALID_KEYS=-14,
    EB_PROCESSDATA_UNWRAP_STATUS_DATA_TOO_SHORT=-10,
    EB_PROCESSDATA_UNWRAP_STATUS_MALFORMED=-11,
    EB_PROCESSDATA_UNWRAP_STATUS_HMAC_INVALID=-12,
    EB_PROCESSDATA_UNWRAP_STATUS_DECRYPTION_ERROR=-2,
    EB_PROCESSDATA_UNWRAP_STATUS_UNEXPECTED_FORMAT=-15,
    EB_PROCESSDATA_UNWRAP_STATUS_GENERAL_ERROR=-1,
    EB_PROCESSDATA_UNWRAP_STATUS_SUCCESS=0

}t_ebUnwrapProcessDataResponseCode;

/**
 * Misc SHSM utils.
 */
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
     * Builds user object representation from the object handle, stored in the soft database.
     */
    static std::shared_ptr<ShsmUserObjectInfo> buildShsmUserObjectInfo(SoftDatabase *db, CK_OBJECT_HANDLE hKey, SoftSlot * slot = NULL);

    /**
     * Returns request string for decryption query.
     */
    static std::string getRequestDecrypt(const ShsmPrivateKey * privKey, const Botan::byte byte[], size_t t);

    /**
     * Process ProcessData response, unprotects data, removes rubbish.
     * @param buff - buffer with ProcessData response to unwrap.
     * @param size - size of data in buff to process
     * @param key - EB encryption communication key for AES-256 decryption.
     * @param macKey - EB HMAC communication key for HMAC verification.
     * @param response - unwrapped response will be placed here
     * @param nonceBuff - buffer where to place extracted nonce from the response. Has to be at least SHSM_FRESHNESS_NONCE_LEN B.
     *      if NULL, nonce from the response is not used.
     * @param responseUOID - if non-NULL, user object ID found in the response is written here
     * @return return code of the operation. 0 returned on success. Negative otherwise.
     */
    static int readProtectedData(Botan::byte * buff, size_t size,
                                 BotanSecureByteKey key, BotanSecureByteKey macKey,
                                 Botan::SecureVector<Botan::byte> ** result,
                                 Botan::byte * nonceBuff = NULL,
                                 SHSM_KEY_HANDLE * responseUOID = NULL);

    /**
     * Removes PKCS1.5 padding from the input buffer and places output to the output buffer.
     * Returns size of the unpadded data in the output buffer or negative in case of a padding failure.
     * Output buffer can be also the input buffer, so it is done in-place.
     */
    static ssize_t removePkcs15Padding(const Botan::byte * buff, size_t len, Botan::byte * out, size_t maxLen, int * status);

    /**
     * Demangles nonce in the processData response to the original one.
     */
    static void demangleNonce(Botan::byte *buff, size_t len);

    /**
     * Adds Shsm crypto engine to Botan, sets preferences.
     */
    static void addShsmEngine2Botan();
};


#endif //SOFTHSMV1_SHSMUTILS_H
