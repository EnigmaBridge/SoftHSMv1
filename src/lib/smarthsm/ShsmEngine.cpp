//
// Created by Dusan Klinec on 16.04.16.
//

#include "ShsmEngine.h"
#include "ShsmPrivateKey.h"
#include "ShsmRsaPrivateOperation.h"

using namespace Botan;

PK_Ops::Signature*
ShsmEngine::get_signature_op(const Private_Key& key) const
{
#if defined(BOTAN_HAS_RSA)
    if(const ShsmPrivateKey* s = dynamic_cast<const ShsmPrivateKey*>(&key))
        return new ShsmRsaPrivateOperation(*s);
#endif

    return 0;
}

PK_Ops::Decryption*
ShsmEngine::get_decryption_op(const Private_Key& key) const
{
#if defined(BOTAN_HAS_RSA)
    if(const ShsmPrivateKey* s = dynamic_cast<const ShsmPrivateKey*>(&key))
        return new ShsmRsaPrivateOperation(*s);
#endif

    return 0;
}

