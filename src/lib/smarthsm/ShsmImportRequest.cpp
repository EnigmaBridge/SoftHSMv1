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


