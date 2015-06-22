//
// Created by Dusan Klinec on 21.06.15.
//

#ifndef SOFTHSMV1_PK_HSMPRIVATEKEY_H
#define SOFTHSMV1_PK_HSMPRIVATEKEY_H
#include <botan/rsa.h>
#include "ShsmApiUtils.h"

class ShsmPrivateKey : public Botan::RSA_PrivateKey {

public:

    ShsmPrivateKey(Botan::RandomNumberGenerator &rng, size_t bits, size_t exp, unsigned long keyId) : RSA_PrivateKey(
            rng, bits, exp), keyId(keyId) { }

    ShsmPrivateKey(Botan::RandomNumberGenerator &rng, size_t bits, size_t exp) : RSA_PrivateKey(rng, bits, exp) { }

    ShsmPrivateKey(Botan::RandomNumberGenerator &rng, const Botan::BigInt &p, const Botan::BigInt &q,
                   const Botan::BigInt &e, const Botan::BigInt &d, const Botan::BigInt &n) : RSA_PrivateKey(rng, p, q, e, d, n) { }

    ShsmPrivateKey(Botan::RandomNumberGenerator &rng, const Botan::BigInt &p, const Botan::BigInt &q,
                   const Botan::BigInt &e, const Botan::BigInt &d, const Botan::BigInt &n, SHSM_KEY_HANDLE shsmHandle) :
            RSA_PrivateKey(rng, p, q, e, d, n), keyId(shsmHandle) { }

    ShsmPrivateKey(const Botan::AlgorithmIdentifier &alg_id, const Botan::MemoryRegion<Botan::byte> &key_bits,
                   Botan::RandomNumberGenerator &rng) : RSA_PrivateKey(alg_id, key_bits, rng) { }

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

protected:
    SHSM_KEY_HANDLE keyId;
};


#endif //SOFTHSMV1_PK_HSMPRIVATEKEY_H