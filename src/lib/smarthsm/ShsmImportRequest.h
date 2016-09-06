//
// Created by Dusan Klinec on 06.09.16.
//

#ifndef SOFTHSMV1_SHSMIMPORTREQUEST_H
#define SOFTHSMV1_SHSMIMPORTREQUEST_H


#include <botan/types.h>
#include <src/common/ShsmApiUtils.h>

class ShsmImportRequest {
public:

    ShsmImportRequest(): tpl(NULL) {};

    virtual ~ShsmImportRequest();

    /**
     * Generates random COMM keys.
     */
    void generateCommKeys();

    /**
     * Sets hexcoded template
     * @param tplHex
     * @return
     */
    int setTpl(std::string tplHex);

    const BotanSecureByteKey &getCommEncKey() const {
        return commEncKey;
    }

    const BotanSecureByteKey &getCommMacKey() const {
        return commMacKey;
    }

    BotanSecureByteVector & getTpl() const {
        return tpl;
    }

    BotanSecureByteVector &getTplPrepared() const {
        return tplPrepared;
    }

    void setTplPrepared(BotanSecureByteVector &tplPrepared) {
        ShsmImportRequest::tplPrepared = tplPrepared;
    }

    ssize_t getTplSize() const {
        return tpl.size();
    }

private:
    BotanSecureByteVector tpl;
    BotanSecureByteVector tplPrepared;
    BotanSecureByteKey commEncKey;
    BotanSecureByteKey commMacKey;
};


#endif //SOFTHSMV1_SHSMIMPORTREQUEST_H
