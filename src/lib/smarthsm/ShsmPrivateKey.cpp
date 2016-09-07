//
// Created by Dusan Klinec on 21.06.15.
//

#include "ShsmPrivateKey.h"
#include "log.h"

std::string ShsmPrivateKey::algo_name() const {
    return "RSA";
}

size_t ShsmPrivateKey::max_input_bits() const {
    return n.bits() - 1;
}

Botan::AlgorithmIdentifier ShsmPrivateKey::algorithm_identifier() const {
    return Botan::AlgorithmIdentifier();
}

Botan::MemoryVector<Botan::byte> ShsmPrivateKey::x509_subject_public_key() const {
    return Botan::MemoryVector<Botan::byte>(0);
}

SHSM_KEY_HANDLE ShsmPrivateKey::getKeyId() const {
    return uo ? uo->getKeyId() : SHSM_INVALID_KEY_HANDLE;
}

void ShsmPrivateKey::setUo(const std::shared_ptr<ShsmUserObjectInfo> &uo) {
    this->uo = uo;
}
