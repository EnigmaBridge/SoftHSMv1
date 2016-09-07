//
// Created by Dusan Klinec on 06.09.16.
//

#ifndef SOFTHSMV1_SHSMIMPORTREQUEST_H
#define SOFTHSMV1_SHSMIMPORTREQUEST_H


#include <botan/types.h>
#include <src/common/ShsmApiUtils.h>

class ShsmImportRequest {
public:

    ShsmImportRequest(){};

    virtual ~ShsmImportRequest();

    /**
     * Generates random COMM keys.
     */
    void generateCommKeys();

    const BotanSecureByteKey &getCommEncKey() const {
        return commEncKey;
    }

    const BotanSecureByteKey &getCommMacKey() const {
        return commMacKey;
    }

    BotanSecureByteVector const & getTpl() const {
        return tpl;
    }

    BotanSecureByteVector const & getTplPrepared() const {
        return tplPrepared;
    }

    void setTpl(const BotanSecureByteVector &tpl) {
        ShsmImportRequest::tpl = tpl;
    }

    void setTplPrepared(BotanSecureByteVector &tplPrepared) {
        ShsmImportRequest::tplPrepared = tplPrepared;
    }

    ssize_t getTplSize() const {
        return tpl.size();
    }

    const Json::Value &getImportKey() const {
        return importKey;
    }

    void setImportKey(const Json::Value &importKey) {
        ShsmImportRequest::importKey = importKey;
    }

    const Json::Value &getAuthorization() const {
        return authorization;
    }

    void setAuthorization(const Json::Value &authorization) {
        ShsmImportRequest::authorization = authorization;
    }

    const Json::Value &getObjectId() const {
        return objectId;
    }

    void setObjectId(const Json::Value &objectId) {
        ShsmImportRequest::objectId = objectId;
    }

private:
    BotanSecureByteVector tpl;
    BotanSecureByteVector tplPrepared;
    BotanSecureByteKey commEncKey;
    BotanSecureByteKey commMacKey;
    Json::Value importKey;
    Json::Value authorization;
    Json::Value objectId;
};


#endif //SOFTHSMV1_SHSMIMPORTREQUEST_H
