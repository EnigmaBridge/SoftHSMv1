/* $Id$ */

/*
 * Copyright (c) 2008 .SE (The Internet Infrastructure Foundation).
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

// Returns the directory where the private keys are stored.
// They are stored in the .softHSM directory in the user's
// home directory.

char* checkHSMDir() {
  char *homeDir = getenv("HOME");
  char *directory = (char*)malloc(strlen(homeDir) + 10);

  snprintf(directory, strlen(homeDir) + 10, "%s/.softHSM", homeDir);

  struct stat st;

  // Create the directory if it is not present.
  if(stat(directory, &st) != 0) {
    mkdir(directory, S_IRUSR | S_IWUSR | S_IXUSR);
  }

  return directory;
}

// Return a new file-name/label/ID
// It is the current date/time down to microseconds
// This should be enough collision resistant.

char* getNewFileName() {
  char *fileName = (char *)malloc(19);

  struct timeval now;
  gettimeofday(&now, NULL);
  struct tm *timeinfo = gmtime(&now.tv_sec);

  snprintf(fileName, 19, "%02u%02u%02u%02u%02u%02u%06u", timeinfo->tm_year - 100, timeinfo->tm_mon + 1, timeinfo->tm_mday, 
           timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, (unsigned int)now.tv_usec);

  return fileName;
}

// Return the path for a given file name.

char* getFilePath(char *fileName) {
  if(fileName == NULL_PTR) {
    return NULL_PTR;
  }

  char *directory = checkHSMDir();
  char *filePath = (char *)malloc(strlen(directory) + 24);

  snprintf(filePath, strlen(directory) + 24, "%s/%s.pem", directory, fileName);

  free(directory);
  return filePath;
}

// Save the private key on disk.
// It is encrypted with the PIN

bool saveKeyFile(SoftHSMInternal *pSoftH, char *fileName, Private_Key *key) {
  if(fileName == NULL_PTR || key == NULL_PTR || pSoftH == NULL_PTR || !pSoftH->isLoggedIn()) {
    return false;
  }

  std::ofstream priv(getFilePath(fileName));
  AutoSeeded_RNG *rng = pSoftH->rng;

  if(priv.fail()) {
    return false;
  }

  priv << PKCS8::PEM_encode(*key, *rng, pSoftH->getPIN());
  priv.close();

  return true;
}

// Removes the key file, if the user has the correct PIN.

bool removeKeyFile(SoftHSMInternal *pSoftH, char *fileName) {
  if(pSoftH == NULL_PTR || fileName == NULL_PTR || !pSoftH->isLoggedIn()) {
    return false;
  }

  Private_Key *privkey;
  AutoSeeded_RNG *rng = pSoftH->rng;
  char *filePath = getFilePath(fileName);

  // Check if the PIN is correct.
  try {
    privkey = PKCS8::load_key(filePath, *rng, pSoftH->getPIN());
  }
  catch(Botan::Exception e) {
    free(filePath);
    return false;
  }

  if(remove(filePath) != 0) {
    free(filePath);
    return false;
  } else {
    free(filePath);
    return true;
  }
}

// Read all key pairs from the disk to the internal buffer.

void readAllKeyFiles(SoftHSMInternal *pSoftH) {
  DIR *dir = opendir(checkHSMDir());
  struct dirent *entry;
  char *file = NULL_PTR;

  while ((entry = readdir(dir)) != NULL) {
    if(strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
      file = strtok(entry->d_name,".");
      readKeyFile(pSoftH, file);
    }
  }

  closedir(dir);
}

// Read a single key pair from disk to the internal buffer.

CK_RV readKeyFile(SoftHSMInternal *pSoftH, char* file) {
  if(pSoftH == NULL_PTR || file == NULL_PTR) {
    return CKR_GENERAL_ERROR;
  }

  if(!pSoftH->isLoggedIn()) {
    return CKR_USER_NOT_LOGGED_IN;
  }

  Private_Key *privkey;
  AutoSeeded_RNG *rng = pSoftH->rng;
  CK_RV result;

  try {
    privkey = PKCS8::load_key(getFilePath(file), *rng, pSoftH->getPIN());
  }
  catch(Botan::Decoding_Error e) {
    return CKR_USER_NOT_LOGGED_IN;
  }
  catch(Botan::Exception e) {
    return CKR_GENERAL_ERROR;
  }

  // Create new objects.
  SoftObject *privateKey = new SoftObject();
  SoftObject *publicKey = new SoftObject();

  // Add the key to the object.
  result = privateKey->addKey(privkey, CKO_PRIVATE_KEY, file);
  if(result != CKR_OK) {
    // Should we do any clean up?
    return result;
  }

  // Add the key to the object.
  result = publicKey->addKey(privkey, CKO_PUBLIC_KEY, file);
  if(result != CKR_OK) {
    // Should we do any clean up?
    return result;
  }

  // Add the keys to the token.
  int privateRef = pSoftH->addObject(privateKey);
  int publicRef = pSoftH->addObject(publicKey);

  if(!publicRef || !privateRef) {
    // Should we do any clean up?
    return CKR_DEVICE_MEMORY;
  }

  return CKR_OK;
}