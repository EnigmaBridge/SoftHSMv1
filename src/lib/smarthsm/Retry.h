//
// Created by Dusan Klinec on 06.09.16.
//

#ifndef SOFTHSMV1_RETRY_H
#define SOFTHSMV1_RETRY_H


#include <src/json/json.h>

class Retry {

public:

    Retry(): maxRetry(3), jitterBase(30), jitterRand(10) {}

    Retry(unsigned int maxRetry, int jitterBase, int jitterRand) : maxRetry(maxRetry), jitterBase(jitterBase),
                                                                   jitterRand(jitterRand) {}

    Retry(const Retry& other) :
            maxRetry(other.maxRetry),
            jitterBase(other.jitterBase),
            jitterRand(other.jitterRand) {}

    void configure(const Json::Value & config);

    int genJitter() const;

    void sleepJitter() const;

    unsigned int getMaxRetry() const {
        return maxRetry;
    }

    void setMaxRetry(unsigned int maxRetry) {
        Retry::maxRetry = maxRetry;
    }

    int getJitterBase() const {
        return jitterBase;
    }

    void setJitterBase(int jitterBase) {
        Retry::jitterBase = jitterBase;
    }

    int getJitterRand() const {
        return jitterRand;
    }

    void setJitterRand(int jitterRand) {
        Retry::jitterRand = jitterRand;
    }

private:
    unsigned maxRetry;
    int jitterBase;
    int jitterRand;
};


#endif //SOFTHSMV1_RETRY_H
