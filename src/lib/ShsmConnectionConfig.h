//
// Created by Dusan Klinec on 19.06.15.
//

#ifndef SOFTHSMV1_SHSMCONNECTIONCONFIG_H
#define SOFTHSMV1_SHSMCONNECTIONCONFIG_H

#include <string>
#include <botan/rsa.h>

class ShsmConnectionConfig {
protected:
    const static int         SHSM_PORT_DEFAULT;
    const static std::string SHSM_HOST_DEFAULT;
    const static int         REQUEST_TIMEOUT_DEFAULT;

    std::string  mHost;
    int          mPort;
    int          mTimeout;

    /**
     * Encryption key used for communication with SHSM.
     */
    std::string key;

    //RSAPublicKey m_shsmPubKey = null;

    /**
     * Public key for the SHSM to be loaded during first connection.
     */
    Botan::RSA_PublicKey * shsmPubKey;

public:

    ShsmConnectionConfig(const std::string &mHost, int mPort) : mHost(mHost), mPort(mPort), mTimeout(REQUEST_TIMEOUT_DEFAULT) { }


    ShsmConnectionConfig(const std::string &mHost, int mPort, int mTimeout) : mHost(mHost), mPort(mPort),
                                                                                 mTimeout(mTimeout) { }

    const std::string &getMHost() const {
        return mHost;
    }

    void setMHost(const std::string &mHost) {
        ShsmConnectionConfig::mHost = mHost;
    }

    int getMPort() const {
        return mPort;
    }

    void setMPort(int mPort) {
        ShsmConnectionConfig::mPort = mPort;
    }

    int getMTimeout() const {
        return mTimeout;
    }

    void setMTimeout(int mTimeout) {
        ShsmConnectionConfig::mTimeout = mTimeout;
    }


    const std::string &getKey() const {
        return key;
    }

    void setKey(const std::string &key) {
        ShsmConnectionConfig::key = key;
    }

    Botan::RSA_PublicKey *getShsmPubKey() const {
        return shsmPubKey;
    }

    void setShsmPubKey(Botan::RSA_PublicKey *shsmPubKey) {
        ShsmConnectionConfig::shsmPubKey = shsmPubKey;
    }
};


#endif //SOFTHSMV1_SHSMCONNECTIONCONFIG_H
