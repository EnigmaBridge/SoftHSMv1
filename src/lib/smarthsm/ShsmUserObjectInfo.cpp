//
// Created by Dusan Klinec on 15.04.16.
//

#include "ShsmUserObjectInfo.h"

std::string ShsmUserObjectInfo::resolveApiKey() const {
    std::string val;
    if (apiKey && !(apiKey.get()->empty())){
        val = *(apiKey.get());

    } else if (slot != nullptr){
        val = slot->getApiKey();
    }

    return val;
}

std::string ShsmUserObjectInfo::resolveHostname() const {
    std::string val;
    if (hostname && !(hostname.get()->empty())){
        val = *(hostname.get());

    } else if (slot != nullptr){
        val = slot->getHost();
    }

    return val;
}

int ShsmUserObjectInfo::resolvePort() const {
    if (port > 0){
        return port;
    } else if (slot != nullptr){
        return slot->getPort();
    } else {
        return -1;
    }
}
