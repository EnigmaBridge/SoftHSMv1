/* $Id$ */

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
* Functions for file handling.
* Many of the function calls are POSIX specific.
*
************************************************************/

#include "file.h"
#include "config.h"
#include "log.h"
#include "SoftHSMInternal.h"

// Standard includes
#include <stdio.h>
#include <string.h>

extern SoftHSMInternal *softHSM;

// Reads the config file

CK_RV readConfigFile() {
  FILE *fp;

  fp = fopen(SOFT_CONFIG_FILE,"r");

  if(fp == NULL) {
    #if SOFTLOGLEVEL >= SOFTERROR
      logError("C_Initialize", "Could not open the config file");
    #endif

    return CKR_GENERAL_ERROR;
  }

  char *dbPath = (char *)malloc(257);
  CK_SLOT_ID slotID;
  int length = 0;

  while(fscanf(fp, "%i:%256s\n", &slotID, dbPath) == 2) {
    length = strlen(dbPath);
    char *addDBPath = (char *)malloc(length+1);
    addDBPath[length] = '\0';
    memcpy(addDBPath, dbPath, length);

    softHSM->slots->addSlot(slotID, addDBPath);
    softHSM->slotCount++;
  }

  fclose(fp);

  if(softHSM->slotCount <= 0) {
    return CKR_GENERAL_ERROR;
  }

  return CKR_OK;
}