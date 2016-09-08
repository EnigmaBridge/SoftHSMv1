//
// Created by Dusan Klinec on 06.09.16.
//

#ifndef SOFTHSMV1_SHSMCREATEUO_H
#define SOFTHSMV1_SHSMCREATEUO_H

#include <json.h>
#include <src/lib/SoftSlot.h>
#include "ShsmImportRequest.h"
#include "ShsmUserObjectInfo.h"
#include "ShsmPrivateKey.h"

namespace createUO {
    namespace consts {
        extern const char * const type;
        extern const char * const generation;
        extern const char * const commkey;
        extern const char * const billingkey;
        extern const char * const appkey;

        extern const char * const yes;
        extern const char * const no;

        namespace uoType {
            const int HMAC = 0x0001;
            const int SCRAMBLE = 0x0002;
            const int ENSCRAMBLE = 0x0003;
            const int PLAINAES = 0x0004;
            const int RSA1024DECRYPT_NOPAD = 0x0005;
            const int RSA2048DECRYPT_NOPAD = 0x0006;
            const int EC_FP192SIGN = 0x0007;
            const int AUTH_HOTP = 0x0008;
            const int AUTH_NEW_USER_CTX = 0x0009;
            const int AUTH_PASSWORD = 0x000a;
            const int AUTH_UPDATE_USER_CTX = 0x000b;
            const int TOKENIZE = 0x000c;
            const int DETOKENIZE = 0x000d;
            const int TOKENIZEWRAP = 0x000e;
            const int PLAINAESDECRYPT = 0x000f;
            const int RANDOMDATA = 0x0010;
            const int CREATENEWUO = 0x0011;
            const int RSA1024ENCRYPT_NOPAD = 0x0012;
            const int RSA2048ENCRYPT_NOPAD = 0x0013;
        }

        // Key generation method.
        namespace gen {
            const int LEGACY_RANDOM=0;
            const int CLIENT=1;
            const int COMP1=2;
            const int COMP2=3;
            const int COMP3=4;
            const int SERVER_RANDOM=5;
            const int SERVER_DERIVED=6;
        }
    }
}

class ShsmCreateUO {
public:

    /**
     * Returns default getTemplate request specification.
     * @return JSON
     */
    static Json::Value getDefaultTemplateRequestSpec();

    /**
     * Returns get template request specification, using default values if
     * not present in spec.
     *
     * @param spec specification to use. optional.
     * @return
     */
    static Json::Value getTemplateRequestSpec(const Json::Value * spec);

    /**
     * Returns get template request specification, using default values if
     * not present in spec. Uses configuration stored in slot.
     *
     * @param slot specification to use. optional.
     * @return
     */
    static Json::Value getTemplateRequestSpec(SoftSlot * slot);

    /**
     * Sets UO type to the request.
     *
     * @param spec
     * @param type
     */
    static void setType(Json::Value * spec, int type);

    /**
     * Sets type of the create request, for RSA key with given key size.
     *
     * @param spec
     * @param bitSize
     */
    static int setRsaType(Json::Value * spec, int bitSize);

    /**
     * Builds API request block.
     *
     * @param slot
     * @param spec
     * @return
     */
    static Json::Value getTemplateRequest(SoftSlot *slot, const Json::Value * spec);

    /**
     * Calls getUserObjectTemplate()
     *
     * @param slot
     * @param spec
     * @return
     */
    static Json::Value templateRequest(SoftSlot * slot, const Json::Value * spec, int * status = NULL);

    /**
     * Prepares UO template for import.
     *
     * @param slot
     * @param tplReqSpec
     * @return
     */
    static ShsmImportRequest * processTemplate(SoftSlot * slot,
                                               const Json::Value * tplReqSpec,
                                               const Json::Value * tplResp,
                                               int * statusCode);

    /**
     * Encrypts template with symmerical keys.
     * AES-256-CBC + AES-CBC-MAC
     *
     * @param encKey
     * @param macKey
     * @param buffer
     * @return
     */
    static int encryptTemplate(const BotanSecureByteKey & encKey, const BotanSecureByteKey & macKey,
                               size_t encOffset,
                               BotanSecureByteVector & buffer,
                               BotanSecureByteVector & dest
    );

    /**
     * Processes import keys and returns the best one to use.
     *
     * @param importKeys
     * @return
     */
    static Json::Value getBestImportKey(const Json::Value & importKeys);

    /**
     * RSA wrapping with the given JSON key.
     *
     * @param rsaKey
     * @param buffer
     * @return
     */
    static int encryptRSA(const Json::Value & rsaKey, BotanSecureByteVector & buffer, BotanSecureByteVector & dest);

    /**
     * Parses JSON serialized RSA public key.
     *
     * @param rsaKey
     * @param status
     * @return
     */
    static Botan::RSA_PublicKey * readSerializedRSAPubKey(const Json::Value & rsaKey, int * status);

    /**
     * Parses serialized public key.
     *
     * @param rsaKey
     * @param status
     * @return
     */
    static Botan::RSA_PublicKey * readSerializedRSAPubKey(const std::string & rsaKey, int * status);

    /**
     * Converts hex encoded byte array to secure byte vector.
     *
     * @param hex
     * @param vector
     * @return
     */
    static int parseHexToVector(std::string hex, BotanSecureByteVector & vector);

    /**
     * Calls importUO()
     *
     * @param slot
     * @param req
     * @param status
     * @return
     */
    static Json::Value importObject(SoftSlot * slot, ShsmImportRequest * req, int * status = NULL);

    /**
     * Creates UOInfo object from the import response.
     *
     * @param slot
     * @param req
     * @param importResp
     * @return
     */
    static ShsmUserObjectInfo * buildImportedObject(SoftSlot * slot,
                                                    ShsmImportRequest * req,
                                                    const Json::Value & importResp,
                                                    int * status);

    /**
     * Creates Shsm private key from the imported (HSM generated) private key.
     *
     * @param slot
     * @param req
     * @param importResp
     * @param status
     * @return
     */
    static ShsmPrivateKey * buildImportedPrivateKey(SoftSlot * slot,
                                                    ShsmImportRequest * req,
                                                    const Json::Value & importResp,
                                                    int * status);

    /**
     * Wrapping function that handles the whole RSA key creation.
     *
     * @param slot
     * @param extraSpec
     * @param bitSize
     * @param status
     * @return
     */
    static ShsmPrivateKey * createNewRsaKey(SoftSlot * slot, Json::Value * extraSpec, int bitSize, int* status);
};


#endif //SOFTHSMV1_SHSMCREATEUO_H
