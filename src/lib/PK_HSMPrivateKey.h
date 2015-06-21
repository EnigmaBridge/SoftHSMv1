//
// Created by Dusan Klinec on 21.06.15.
//

#ifndef SOFTHSMV1_PK_HSMPRIVATEKEY_H
#define SOFTHSMV1_PK_HSMPRIVATEKEY_H


class PK_HSMPrivateKey {


public:
    unsigned long getKeyId() const {
        return keyId;
    }

    void setKeyId(unsigned long keyId) {
        PK_HSMPrivateKey::keyId = keyId;
    }

protected:
    unsigned long keyId;
};


#endif //SOFTHSMV1_PK_HSMPRIVATEKEY_H
