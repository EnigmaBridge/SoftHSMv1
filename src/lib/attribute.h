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

#ifndef SOFTHSM_ATTRIBUTE_H
#define SOFTHSM_ATTRIBUTE_H 1

#include "cryptoki.h"

// Includes for the crypto library
#include <botan/rng.h>

// Boolean attribute for private keys, if set to true, the private key is stored in SHSM.
#define CKA_SHSM_KEY (CKA_VENDOR_DEFINED + 0x100)
// Integer attribute, stores private key handle for SHSM stored private key.
#define CKA_SHSM_KEY_HANDLE (CKA_VENDOR_DEFINED + 0x101)
// RSA private key type stored in SHSM.
#define CKO_PRIVATE_KEY_SHSM (CKO_VENDOR_DEFINED + CKO_PRIVATE_KEY)

// Type of the SHSM_KEY_HANDLE.
#define SHSM_KEY_HANDLE long
#define SHSM_INVALID_KEY_HANDLE -1

CK_RV valAttributeCertificate(CK_STATE state, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV valAttributePubRSA(CK_STATE state, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV valAttributePrivRSA(CK_STATE state, Botan::RandomNumberGenerator *rng, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

#endif /* SOFTHSM_ATTRIBUTE_H */
