//
// Created by Dusan Klinec on 18.06.15.
//

#ifndef SOFTHSMV1_PK_DECRYPTOR_EME_REMOTE_H
#define SOFTHSMV1_PK_DECRYPTOR_EME_REMOTE_H

#include "main.h"
#include "log.h"
#include "botan_compat.h"
#include "file.h"
#include "SoftHSMInternal.h"
#include "userhandling.h"
#include "util.h"
#include "mechanisms.h"
#include "string.h"
#include "MutexFactory.h"

// Standard includes
#include <stdio.h>
#include <stdlib.h>
#include <memory>
#include <sstream>

// C POSIX library header
#include <sys/time.h>

// Includes for the crypto library
#include <botan/init.h>
#include <botan/pubkey.h>
#include <botan/libstate.h>
#include <botan/md5.h>
#include <botan/rmd160.h>
#include <botan/sha160.h>
#include <botan/sha2_32.h>
#include <botan/sha2_64.h>
#include <botan/filters.h>
#include <botan/pipe.h>
#include <botan/emsa3.h>
#include <botan/emsa4.h>
#include <botan/emsa_raw.h>
#include <botan/eme_pkcs.h>
#include <botan/pk_keys.h>
#include <botan/bigint.h>
#include <botan/rsa.h>
#include <pkcs11.h>
#include "ShsmConnectionConfig.h"
#include "ShsmPrivateKey.h"
#include <json/json.h>
#include <json/json-forwards.h>

/**
 * Class for PK decryption using remote call to HSM.
 */
class PK_Decryptor_EME_Remote : public Botan::PK_Decryptor {
protected:
    /**
     * Connection configuration to use for decryption call.
     */
    ShsmConnectionConfig * connectionConfig = NULL;

    /**
     * Private key information. Key is stored in HSM, this object contains information to reach it via remote calls.
     */
    ShsmPrivateKey * privKey = NULL;

    /**
     * Keep padding information also here.
     */
    std::string eme;

public:
    PK_Decryptor_EME_Remote(ShsmPrivateKey * key, const std::string &eme,
                            const SoftSlot * curSlot);

    const ShsmConnectionConfig * getConnectionConfig() const {
        return connectionConfig;
    }

    void setConnectionConfig(ShsmConnectionConfig * connectionConfig) {
        PK_Decryptor_EME_Remote::connectionConfig = connectionConfig;
    }

private:
    virtual Botan::SecureVector<Botan::byte> dec(const Botan::byte byte[], size_t t) const;

    /**
     * Main method for submitting JSON request for decryption.
     */
    Botan::SecureVector<Botan::byte> decryptCall(const Botan::byte byte[], size_t t, int * status) const;

    /**
     * Tests the whole API with RSA_ENC(plaintextByte) if we obtain the same value after RSA decryption.
     */
    void testCallWithByte(Botan::byte plaintextByte, bool pkcs15padding) const;

};


#endif //SOFTHSMV1_PK_DECRYPTOR_EME_REMOTE_H
