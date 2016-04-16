//
// Created by Dusan Klinec on 16.04.16.
//

#ifndef SOFTHSMV1_SHSMENGINE_H
#define SOFTHSMV1_SHSMENGINE_H

#include <botan/engine.h>

class ShsmEngine : public Botan::Engine
{
public:
    ShsmEngine() {};
    ~ShsmEngine() {};

    std::string provider_name() const { return "shsm"; }

    Botan::PK_Ops::Signature* get_signature_op(const Botan::Private_Key& key) const;

    Botan::PK_Ops::Decryption* get_decryption_op(const Botan::Private_Key& key) const;

};



#endif //SOFTHSMV1_SHSMENGINE_H
