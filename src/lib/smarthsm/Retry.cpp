//
// Created by Dusan Klinec on 06.09.16.
//

#include "Retry.h"
#include "ShsmUtils.h"

#define FLD_RETRY "retry"
#define FLD_MAX_RETRY "maxRetry"
#define FLD_JITTER_BASE "jitterBase"
#define FLD_JITTER_RAND "jitterRand"

void Retry::configure(const Json::Value & config) {
    if (!config[FLD_RETRY].isNull()) {
        this->configure(config[FLD_RETRY]);
        return;
    }

    if (!config[FLD_RETRY][FLD_MAX_RETRY].isNull()){
        this->maxRetry = config[FLD_RETRY][FLD_MAX_RETRY].asUInt();
    }
    if (!config[FLD_RETRY][FLD_JITTER_BASE].isNull()){
        this->jitterBase = config[FLD_RETRY][FLD_JITTER_BASE].asInt();
    }
    if (!config[FLD_RETRY][FLD_JITTER_RAND].isNull()){
        this->jitterRand = config[FLD_RETRY][FLD_JITTER_RAND].asInt();
    }
}

int Retry::genJitter() const{
    return this->jitterBase + (ShsmApiUtils::randomInt() % (2*this->jitterRand)) - this->jitterRand;
}

void Retry::sleepJitter() const {
    ShsmUtils::sleepcp(this->genJitter());
}
