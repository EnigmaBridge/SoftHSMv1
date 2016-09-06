//
// Created by Dusan Klinec on 06.09.16.
//

#include <src/lib/log.h>
#include "ShsmImportRequest.h"
#define TAG "ShsmImportReq: "

void ShsmImportRequest::generateCommKeys() {
    commEncKey.resize(SHSM_COMM_KEY_ENC_SIZE);
    commMacKey.resize(SHSM_COMM_KEY_MAC_SIZE);
    ShsmApiUtils::rng().randomize(commEncKey.begin(), SHSM_COMM_KEY_ENC_SIZE);
    ShsmApiUtils::rng().randomize(commMacKey.begin(), SHSM_COMM_KEY_MAC_SIZE);
}

ShsmImportRequest::~ShsmImportRequest() {

}

int ShsmImportRequest::setTpl(std::string tplHex) {
    size_t len = (size_t)ShsmApiUtils::getJsonByteArraySize(tplHex);
    if (len <= 0){
        ERROR_MSGF(TAG"Template hex format invalid");
        return 1;
    }

    this->tpl.resize(len);
    size_t realSize = ShsmApiUtils::hexToBytes(tplHex, this->tpl.begin(), (size_t) len);
    this->tpl.resize(realSize);
    return 0;
}

