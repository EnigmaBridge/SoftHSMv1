/*
 * Copyright (c) 2008-2009 .SE (The Internet Infrastructure Foundation).
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/************************************************************
*
* This class defines a session
* It holds the current state of the session
*
************************************************************/

#include "SoftSession.h"
#include "util.h"
#include "attribute.h"

// Includes for the crypto library
#include <botan/libstate.h>
#include <botan/if_algo.h>
#include <botan/rsa.h>
#include <pkcs11.h>
#include "ShsmPrivateKey.h"
#include "ShsmUtils.h"
#include "log.h"

SoftSession::SoftSession(CK_FLAGS rwSession, SoftSlot *givenSlot, char *appID) {
  pApplication = NULL_PTR;
  Notify = NULL_PTR;

  if(rwSession == CKF_RW_SESSION) {
    readWrite = true;
  } else {
    readWrite = false;
  }

  findAnchor = NULL_PTR;
  findCurrent = NULL_PTR;
  findInitialized = false;

  digestPipe = NULL_PTR;
  digestSize = 0;
  digestInitialized = false;

  pkEncryptor = NULL_PTR;
  encryptSinglePart = false;
  encryptSize = 0;
  encryptInitialized = false;

  pkDecryptor = NULL_PTR;
  decryptSinglePart = false;
  decryptSize = 0;
  decryptInitialized = false;

  pkSigner = NULL_PTR;
  signSinglePart = false;
  signSize = 0;
  signInitialized = false;
  signMech = CKM_VENDOR_DEFINED;
  signKey = CK_INVALID_HANDLE;

  pkVerifier = NULL_PTR;
  verifySinglePart = false;
  verifySize = 0;
  verifyInitialized = false;

  keyStore = new SoftKeyStore();

  rng = new Botan::AutoSeeded_RNG();

  currentSlot = givenSlot;

  db = new SoftDatabase(appID);
  if(db->init(currentSlot->dbPath) != CKR_OK) {
    delete db;
    db = NULL_PTR;
  }
}

SoftSession::~SoftSession() {
  pApplication = NULL_PTR;
  Notify = NULL_PTR;

  DELETE_PTR(findAnchor);
  findCurrent = NULL_PTR;

  // Another PKCS#11 library may have finalized Botan before we close the session.
  // It will not help to reinitialize Botan, since it requires the same
  // instance of Botan memory allocator. The memory leak will only happen
  // when the two PKCS#11 libraries using Botan are closing down.

  // Check if Botan is initialized
#ifdef BOTAN_PRE_1_9_10_FIX
  Botan::Library_State* state = Botan::swap_global_state(0);
  Botan::swap_global_state(state);

  if(state) {
#else
  if(Botan::Global_State_Management::global_state_exists()) {
#endif
    DELETE_PTR(digestPipe);
    DELETE_PTR(pkEncryptor);
    DELETE_PTR(pkDecryptor);
    DELETE_PTR(pkSigner);
    DELETE_PTR(pkVerifier);
    DELETE_PTR(keyStore);
    DELETE_PTR(rng);
  }

  DELETE_PTR(db);
}

bool SoftSession::isReadWrite() {
  return readWrite;
}

// Get the key from the session key store
// If it is not chached then create a clone
// of it and store it in the cache.

Botan::Public_Key* SoftSession::getKey(CK_OBJECT_HANDLE hKey) {
  Botan::Public_Key* tmpKey = keyStore->getKey(hKey);

  // If the key is not in the session cache
  if(tmpKey == NULL_PTR) {
    // Load key type.
    const CK_KEY_TYPE keyType = this->db->getKeyType(hKey);
    if(keyType == CKK_RSA) {
      // Clone the key
      const CK_OBJECT_CLASS objClass = this->db->getObjectClass(hKey);
      // Is the private key stored in the SHSM?
      bool isShsm = ShsmUtils::isShsmKey(this->db, hKey);
      if(objClass == CKO_PRIVATE_KEY && !isShsm) {
        Botan::BigInt bigN = this->db->getBigIntAttribute(hKey, CKA_MODULUS);
        Botan::BigInt bigE = this->db->getBigIntAttribute(hKey, CKA_PUBLIC_EXPONENT);
        Botan::BigInt bigD = this->db->getBigIntAttribute(hKey, CKA_PRIVATE_EXPONENT);
        Botan::BigInt bigP = this->db->getBigIntAttribute(hKey, CKA_PRIME_1);
        Botan::BigInt bigQ = this->db->getBigIntAttribute(hKey, CKA_PRIME_2);

        if(bigN.is_zero () || bigE.is_zero() || bigD.is_zero() || bigP.is_zero() || bigQ.is_zero()) {
          return NULL_PTR;
        }

        try {
          tmpKey = new Botan::RSA_PrivateKey(*rng, bigP, bigQ, bigE, bigD, bigN);
        }
        catch(...) {
          ERROR_MSG("getKey", "RSA private key init exception");
          return NULL_PTR;
        }

      } else if (objClass == CKO_PRIVATE_KEY && isShsm) {
        // Load attributes related to SHSM RSA private key.
        std::shared_ptr<ShsmUserObjectInfo> uo = ShsmUtils::buildShsmUserObjectInfo(this->db, hKey, this->currentSlot);
        if (!uo){
          ERROR_MSG("getKey", "Invalid SHSM handle");
          return NULL_PTR;
        }

        Botan::BigInt bigN = this->db->getBigIntAttribute(hKey, CKA_MODULUS);
        Botan::BigInt bigE = this->db->getBigIntAttribute(hKey, CKA_PUBLIC_EXPONENT);
        if (bigN.is_zero() || bigE.is_zero()) {
          ERROR_MSG("getKey", "N or E is null for SHSM key");
          return NULL_PTR;
        }

        try {
          DEBUG_MSGF(("SoftSession: ShsmPrivateKey, bigN: %d, bits: %d, handle: %d", bigN.size(), bigN.bits(), uo->getKeyId()));
          tmpKey = new ShsmPrivateKey(bigN, bigE, uo);
        }
        catch(std::exception& e) {
          ERROR_MSG("getKey", "ShsmPrivateKey key init exception");
          DEBUG_MSGF(("SoftSession: Exception: %s, hKey: %ld, bigN: %d, bits: %d", e.what(), hKey, bigN.size(), bigN.bits()));
          return NULL_PTR;
        }

      } else if (objClass == CKO_PUBLIC_KEY) {
        Botan::BigInt bigN = this->db->getBigIntAttribute(hKey, CKA_MODULUS);
        Botan::BigInt bigE = this->db->getBigIntAttribute(hKey, CKA_PUBLIC_EXPONENT);

        if(bigN.is_zero() || bigE.is_zero()) {
          return NULL_PTR;
        }

        try {
          tmpKey = new Botan::RSA_PublicKey(bigN, bigE);
        }
        catch(...) {
          ERROR_MSG("getKey", "RSA_PublicKey key init exception");
          return NULL_PTR;
        }

      } else {
        // ERROR.
        ERROR_MSG("getKey", "Unknown key");
        return NULL_PTR;
      }

      // Create a new key store object.
      SoftKeyStore *newKeyLink = new SoftKeyStore();
      if(newKeyLink == NULL_PTR) {
        return NULL_PTR;
      }
      newKeyLink->next = keyStore;
      newKeyLink->botanKey = tmpKey;
      newKeyLink->index = hKey;

      // Add it first in the chain.
      keyStore = newKeyLink;
    }
  }

  return tmpKey;
}

// Return the current session state

CK_STATE SoftSession::getSessionState() {
  if(currentSlot->soPIN != NULL_PTR) {
    return CKS_RW_SO_FUNCTIONS;
  } else if(currentSlot->userPIN != NULL_PTR) {
    if(readWrite) {
      return CKS_RW_USER_FUNCTIONS;
    } else {
      return CKS_RO_USER_FUNCTIONS;
    }
  } else {
    if(readWrite) {
      return CKS_RW_PUBLIC_SESSION;
    } else {
      return CKS_RO_PUBLIC_SESSION;
    }
  }
}
