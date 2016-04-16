//
// Created by Dusan Klinec on 21.06.15.
//

#ifndef SOFTHSMV1_PK_HSMPRIVATEKEY_H
#define SOFTHSMV1_PK_HSMPRIVATEKEY_H
#include <memory>
#include <botan/rsa.h>
#include "ShsmApiUtils.h"
#include "ShsmUserObjectInfo.h"

class ShsmPrivateKey : public Botan::RSA_PublicKey,
                       public Botan::IF_Scheme_PrivateKey {

public:

    ShsmPrivateKey(const Botan::BigInt n, const Botan::BigInt e, std::shared_ptr<ShsmUserObjectInfo> uoin) : RSA_PublicKey(n, e),
                                                                                 IF_Scheme_PrivateKey(),
                                                                                 uo(uoin) { }

    virtual std::string algo_name() const;

    virtual size_t max_input_bits() const;

    virtual Botan::AlgorithmIdentifier algorithm_identifier() const;

    virtual Botan::MemoryVector<Botan::byte> x509_subject_public_key() const;

    SHSM_KEY_HANDLE getKeyId() const {
        return uo ? uo->getKeyId() : SHSM_INVALID_KEY_HANDLE;
    }

    const std::shared_ptr<ShsmUserObjectInfo> &getUo() const {
        return uo;
    }

    void setUo(const std::shared_ptr<ShsmUserObjectInfo> &uo) {
        ShsmPrivateKey::uo = uo;
    }

protected:
    // User object info.
    std::shared_ptr<ShsmUserObjectInfo> uo;
};


#endif //SOFTHSMV1_PK_HSMPRIVATEKEY_H