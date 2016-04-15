//
// Created by Dusan Klinec on 21.06.15.
//

#ifndef SOFTHSMV1_PK_HSMPRIVATEKEY_H
#define SOFTHSMV1_PK_HSMPRIVATEKEY_H
#include <botan/rsa.h>
#include "ShsmApiUtils.h"

class ShsmPrivateKey : public Botan::RSA_PublicKey,
                       public Botan::IF_Scheme_PrivateKey {

public:

    ShsmPrivateKey(const Botan::BigInt n, const Botan::BigInt e, SHSM_KEY_HANDLE keyId) : RSA_PublicKey(n, e),
                                                                                 IF_Scheme_PrivateKey(),
                                                                                 keyId(keyId), bigN(n), bigE(e) { }

    virtual std::string algo_name() const;

    virtual size_t max_input_bits() const;

    virtual Botan::AlgorithmIdentifier algorithm_identifier() const;

    virtual Botan::MemoryVector<Botan::byte> x509_subject_public_key() const;

    SHSM_KEY_HANDLE getKeyId() const {
        return keyId;
    }

    void setKeyId(SHSM_KEY_HANDLE keyId) {
        ShsmPrivateKey::keyId = keyId;
    }

    const Botan::BigInt &getBigN() const {
        return bigN;
    }

    const Botan::BigInt &getBigE() const {
        return bigE;
    }

protected:
    // User Object ID to EB for private key operation.
    SHSM_KEY_HANDLE keyId;

    // Public parts, moduls, e exponent.
    Botan::BigInt bigN;
    Botan::BigInt bigE;
};


#endif //SOFTHSMV1_PK_HSMPRIVATEKEY_H