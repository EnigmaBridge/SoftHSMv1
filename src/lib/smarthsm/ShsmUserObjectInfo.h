//
// Created by Dusan Klinec on 15.04.16.
//

#ifndef SOFTHSMV1_SHSMUSEROBJECTINFO_H
#define SOFTHSMV1_SHSMUSEROBJECTINFO_H

#include <memory>
#include <src/common/ShsmApiUtils.h>
#include <src/lib/SoftSlot.h>

// Fwd declaration needed.
class SoftSlot;

/**
 * User Object data.
 * User Object (UO) is an SHSM object (e.g., RSA private key, AES encryption key, authentication context ID).
 *
 * In order to use UO, client needs UO identifier (handle), API key, endpoint address and port.
 * Moreover communication keys (encryption, mac) are needed as ProcessData is encrypted+MACed so only
 * secure elements can read it.
 *
 * UO Info stores all necessary information to perform SHSM operation with given UO.
 */
class ShsmUserObjectInfo {
public:
    ShsmUserObjectInfo() : keyId(SHSM_INVALID_KEY_HANDLE), keyType(SHSM_INVALID_KEY_TYPE), port(-1), slot(nullptr) { }

    ShsmUserObjectInfo(SHSM_KEY_HANDLE keyId) : keyId(keyId), port(-1), slot(nullptr) { }

    ShsmUserObjectInfo(SHSM_KEY_HANDLE keyId, SHSM_KEY_TYPE keyType,
                       const std::shared_ptr<BotanSecureByteKey> &encKey,
                       const std::shared_ptr<BotanSecureByteKey> &macKey) : keyId(keyId), keyType(keyType),
                                                                            encKey(encKey), macKey(macKey),
                                                                            port(-1), slot(nullptr) { }

    ShsmUserObjectInfo(SHSM_KEY_HANDLE keyId, SHSM_KEY_TYPE keyType,
                       const std::shared_ptr<BotanSecureByteKey> &encKey,
                       const std::shared_ptr<BotanSecureByteKey> &macKey,
                       const std::shared_ptr<std::string> &apiKey,
                       const std::shared_ptr<std::string> &hostname, int port) : keyId(keyId), keyType(keyType),
                                                                                 encKey(encKey), macKey(macKey),
                                                                                 apiKey(apiKey),
                                                                                 hostname(hostname), port(port),
                                                                                 slot(nullptr) { }
    // ------------------
    // Getters & setters
    long getKeyId() const {
        return keyId;
    }

    void setKeyId(long keyId) {
        ShsmUserObjectInfo::keyId = keyId;
    }

    long getKeyType() const {
        return keyType;
    }

    void setKeyType(long keyType) {
        ShsmUserObjectInfo::keyType = keyType;
    }

    const std::shared_ptr<BotanSecureByteKey> &getEncKey() const {
        return encKey;
    }

    void setEncKey(const std::shared_ptr<BotanSecureByteKey> &encKey) {
        ShsmUserObjectInfo::encKey = encKey;
    }

    const std::shared_ptr<BotanSecureByteKey> &getMacKey() const {
        return macKey;
    }

    void setMacKey(const std::shared_ptr<BotanSecureByteKey> &macKey) {
        ShsmUserObjectInfo::macKey = macKey;
    }

    const std::shared_ptr<std::string> &getApiKey() const {
        return apiKey;
    }

    void setApiKey(const std::shared_ptr<std::string> &apiKey) {
        ShsmUserObjectInfo::apiKey = apiKey;
    }

    const std::shared_ptr<std::string> &getHostname() const {
        return hostname;
    }

    void setHostname(const std::shared_ptr<std::string> &hostname) {
        ShsmUserObjectInfo::hostname = hostname;
    }

    int getPort() const {
        return port;
    }

    void setPort(int port) {
        ShsmUserObjectInfo::port = port;
    }

    SoftSlot *getSlot() const {
        return slot;
    }

    void setSlot(SoftSlot *slot) {
        ShsmUserObjectInfo::slot = slot;
    }

private:
    /**
     * User object identifier in EB.
     * Uniquely identifies particular user object for given API key.
     */
    SHSM_KEY_HANDLE keyId;

    /**
     * User object type.
     * Defines supported operation and key generation type.
     */
    SHSM_KEY_TYPE keyType;

    /**
     * AES-256 symmetric key for communication with EB.
     */
    std::shared_ptr<BotanSecureByteKey> encKey;

    /**
     * HMAC-AES-256-CBC symmetric key for communication with EB.
     */
    std::shared_ptr<BotanSecureByteKey> macKey;

    /**
     * Pointer to string object to take apiKey from.
     * API key for EB access.
     *
     * This may override global configuration, if set. On the other hand if null, one from global configuration should
     * be used.
     */
    std::shared_ptr<std::string> apiKey;

    /**
     * Pointer to string object to take EB endpoint hostname from.
     *
     * This may override global configuration, if set. On the other hand if null, one from global configuration should
     * be used.
     */
    std::shared_ptr<std::string> hostname;

    /**
     * Port number for EB endpoint. If hostname is specified, this port should be taken into account if > 0.
     * Otherwise, default one is used.
     */
    int port;

    /**
     * Slot reference. Optional.
     * Defines the owner of the key.
     *
     * Slot can provide default api key, hostname & port values.
     */
    SoftSlot * slot;
};


#endif //SOFTHSMV1_SHSMUSEROBJECTINFO_H
