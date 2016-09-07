//
// Created by Dusan Klinec on 16.04.16.
//

#ifndef SOFTHSMV1_SHSMPROCESSDATAREQUEST_H
#define SOFTHSMV1_SHSMPROCESSDATAREQUEST_H

#include <string>
#include <botan/types.h>
#include <src/common/ShsmApiUtils.h>

/**
 * Simple wrapper for ProcessData request.
 * Produced by request builder.
 */
class ShsmProcessDataRequest {

public:
    ShsmProcessDataRequest() { }

    Botan::byte *getNonceBytes() const {
        return (Botan::byte *) nonceBytes;
    }

    const Json::Value &getRequest() const {
        return request;
    }

    void setRequest(const Json::Value &request) {
        ShsmProcessDataRequest::request = request;
    }

private:
    Json::Value request;
    Botan::byte nonceBytes[SHSM_FRESHNESS_NONCE_LEN];
};


#endif //SOFTHSMV1_SHSMPROCESSDATAREQUEST_H
