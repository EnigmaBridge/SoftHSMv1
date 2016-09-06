//
// Created by Dusan Klinec on 06.09.16.
//

#include <src/lib/log.h>
#include "ShsmCreateUO.h"
#include "ShsmUtils.h"
#include "Retry.h"
#define TAG "ShsmCreateUO: "

Json::Value ShsmCreateUO::getDefaultTemplateRequestSpec() {
    using namespace createUO;

    Json::Value jReq;
    jReq["format"] = 1;
    jReq["protocol"] = 1;

    jReq["environment"] = "dev"; // shows whether the UO should be for production (live), test (pre-production testing), or dev (development)
    jReq["maxtps"] = "unlimited"; // maximum guaranteed TPS
    jReq["core"] = "empty"; // how many cards have UO loaded permanently
    jReq["persistence"] = "one_minute"; // once loaded onto card, how long will the UO stay there without use (this excludes the "core")
    jReq["priority"] = "default"; // this defines a) priority when the server capacity is fully utilised and it also defines how quickly new copies of UO are installed (pre-empting icreasing demand)
    jReq["separation"] = "time"; // "complete" = only one UO can be loaded on a smartcard at one one time
    jReq["bcr"] = consts::yes; // "yes" will ensure the UO is replicated to provide high availability for any possible service disruption
    jReq["unlimited"] = consts::yes; //  if "yes", we expect the data starts with an IV to initialize decryption of data - this is for communication security
    jReq["clientiv"] = consts::yes; // if "yes", we expect the data starting with a diversification 16B for communication keys
    jReq["clientdiv"] = consts::no;
    jReq["resource"] = "global";
    jReq["credit"] = 32677; // <1-32767>, a limit a seed card can provide to the EB service

    Json::Value jGen;
    jGen[consts::commkey] = consts::gen::SERVER_RANDOM;
    jGen[consts::billingkey] = consts::gen::SERVER_RANDOM;
    jGen[consts::appkey] = consts::gen::SERVER_RANDOM;

    jReq[consts::generation] = jGen;
    return jReq;
}

Json::Value ShsmCreateUO::getTemplateRequestSpec(const Json::Value *spec) {
    Json::Value ret(getDefaultTemplateRequestSpec());

    if (spec != nullptr) {
        ShsmUtils::merge(ret, *spec);
    }

    return ret;
}

void ShsmCreateUO::setType(Json::Value *spec, int type) {
    if (spec == nullptr){
        return;
    }

    (*spec)[createUO::consts::type] = type;
}

Json::Value ShsmCreateUO::getTemplateRequest(SoftSlot *slot, const Json::Value *spec) {
    // Request body
    Json::Value jReq;
    jReq["function"] = "GetUserObjectTemplate";
    jReq["version"] = "1.0";
    jReq["objectid"] = ShsmApiUtils::generateApiObjectId(slot->apiKey, 0x1);
    jReq["nonce"] = ShsmApiUtils::generateNonce(8);
    jReq["data"] = getTemplateRequestSpec(spec);
    return jReq;
}

Json::Value ShsmCreateUO::templateRequest(SoftSlot *slot, const Json::Value *spec) {
    int curRetry = 0;
    Retry retry;
    Json::Value errRet(0); // null error response.

    if (slot->config != nullptr) {
        retry.configure(*slot->config);
    }

    // Template request, nonce will be regenerated.
    Json::Value req = ShsmCreateUO::getTemplateRequest(slot, spec);

    // Do the request with retry. isNull() == true in case of a fail.
    Json::Value resp = ShsmUtils::requestWithRetry(retry, slot->host.c_str(), slot->getEnrollPort(), req);

    return resp;
}




