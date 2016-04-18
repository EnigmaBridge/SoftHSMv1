//
// Created by Dusan Klinec on 16.04.16.
//

#ifndef SOFTHSMV1_SHSMRSAPRIVATEOPERATION_H
#define SOFTHSMV1_SHSMRSAPRIVATEOPERATION_H
#include <botan/engine.h>
#include <botan/pk_ops.h>
#include <botan/rsa.h>
#include "ShsmPrivateKey.h"

/**
 * Private operation capable of working with ShsmPrivateKey.
 * Implements signature operation, decryption operation.
 *
 * ShsmEngine returns this object to operate on given private key.
 * This operation performs private operation, which calls remote
 * SHSM API.
 */
class ShsmRsaPrivateOperation : public Botan::PK_Ops::Signature,
                                public Botan::PK_Ops::Decryption
{
public:
    ShsmRsaPrivateOperation(const ShsmPrivateKey& rsa) :
            privKey(rsa),
            n(rsa.get_n()),
            e(rsa.get_e()),
            n_bits(rsa.get_n().bits())
    {}

    size_t max_input_bits() const { return (n_bits - 1); }

    Botan::SecureVector<Botan::byte> sign(const Botan::byte msg[], size_t msg_len,
                            Botan::RandomNumberGenerator&)
    {
        Botan::BigInt m(msg, msg_len);
        Botan::BigInt x = private_op(m);
        return Botan::BigInt::encode_1363(x, (n_bits + 7) / 8);
    }

    Botan::SecureVector<Botan::byte> decrypt(const Botan::byte msg[], size_t msg_len)
    {
        Botan::BigInt m(msg, msg_len);
        return Botan::BigInt::encode(private_op(m));
    }

private:
    Botan::BigInt private_op(const Botan::BigInt& m) const;

    ShsmPrivateKey privKey;

    const Botan::BigInt n, e;
    size_t n_bits;
};

#endif //SOFTHSMV1_SHSMRSAPRIVATEOPERATION_H
