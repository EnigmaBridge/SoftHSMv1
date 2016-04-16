//
// Created by Dusan Klinec on 16.04.16.
//

#ifndef SOFTHSMV1_SHSMPROCESSDATAREQUEST_H
#define SOFTHSMV1_SHSMPROCESSDATAREQUEST_H

#include <string>
#include <botan/types.h>
#include <src/common/ShsmApiUtils.h>

class ShsmProcessDataRequest {

public:
    ShsmProcessDataRequest() { }

    const std::string &getRequest() const {
        return request;
    }

    Botan::byte *getNonceBytes() const {
        return nonceBytes;
    }


    void setRequest(const std::string &request) {
        ShsmProcessDataRequest::request = request;
    }

private:
    std::string request;
    Botan::byte nonceBytes[SHSM_FRESHNESS_NONCE_LEN];
};


#endif //SOFTHSMV1_SHSMPROCESSDATAREQUEST_H
