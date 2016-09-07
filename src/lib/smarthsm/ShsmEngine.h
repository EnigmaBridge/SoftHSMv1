//
// Created by Dusan Klinec on 16.04.16.
//

#ifndef SOFTHSMV1_SHSMENGINE_H
#define SOFTHSMV1_SHSMENGINE_H

#include <botan/engine.h>

/**
 * Botan Crypto engine, using smartHSM for performing the operations.
 * Engine can provide various operations or algorithms.
 *
 * For now it provides signature operation and decryption operation for
 * ShsmPrivateKeys. Basically it supports RSA private operations, where
 * private keys are stored in SHSM.
 */
class ShsmEngine : public Botan::Engine
{
public:
    ShsmEngine() {};
    ~ShsmEngine() {};

    static std::string get_name() { return "shsm"; }

    std::string provider_name() const { return get_name(); }

    Botan::PK_Ops::Signature* get_signature_op(const Botan::Private_Key& key) const;

    Botan::PK_Ops::Verification* get_verify_op(const Botan::Public_Key& key) const;

    Botan::PK_Ops::Decryption* get_decryption_op(const Botan::Private_Key& key) const;

    Botan::PK_Ops::Encryption* get_encryption_op(const Botan::Public_Key& key) const;

};



#endif //SOFTHSMV1_SHSMENGINE_H
