//
// Created by Dusan Klinec on 16.04.16.
//

#ifndef SOFTHSMV1_SHSMPROCESSDATAREQUESTBUILDER_H
#define SOFTHSMV1_SHSMPROCESSDATAREQUESTBUILDER_H


#include "ShsmProcessDataRequest.h"
#include "ShsmUserObjectInfo.h"

/**
 * Request builder for ProcessData requests.
 */
class ShsmProcessDataRequestBuilder {
public:
    ShsmProcessDataRequestBuilder():
            uo(NULL),
            requestType(EB_REQUEST_TYPE_MAX),
            bodyBuff(NULL),
            bodyBuffLen(0),
            statusCode(-1){ }

    ShsmProcessDataRequest * buildProcessDataRequest(const Botan::byte *const body, size_t bodyLen);

    static ShsmProcessDataRequest * buildProcessDataRequest(const Botan::byte *const body, size_t bodyLen,
                                                            ShsmUserObjectInfo *uo,
                                                            t_eb_request_type requestType,
                                                            Botan::byte * bodyBuff,
                                                            size_t bodyBuffLen,
                                                            int * statusCode);

    ShsmProcessDataRequestBuilder * setUo(ShsmUserObjectInfo *uo) {
        ShsmProcessDataRequestBuilder::uo = uo;
        return this;
    }

    ShsmProcessDataRequestBuilder * setRequestType(const t_eb_request_type &requestType) {
        ShsmProcessDataRequestBuilder::requestType = requestType;
        return this;
    }

    ShsmProcessDataRequestBuilder * setBodyBuff(Botan::byte *bodyBuff, size_t bodyBuffLen) {
        ShsmProcessDataRequestBuilder::bodyBuff = bodyBuff;
        ShsmProcessDataRequestBuilder::bodyBuffLen = bodyBuffLen;
        return this;
    }

private:
    ShsmUserObjectInfo *uo;
    t_eb_request_type requestType;

    Botan::byte * bodyBuff;
    size_t bodyBuffLen;

    int statusCode;

};


#endif //SOFTHSMV1_SHSMPROCESSDATAREQUESTBUILDER_H
