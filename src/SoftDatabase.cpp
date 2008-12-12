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
* This class handles the database.
*
************************************************************/

#include "SoftDatabase.h"
#include "file.h"

// Standard includes
#include <string>
#include <sstream>
using std::stringstream;
using std::string;

static char sqlCreateTableObjects[] = 
  "CREATE TABLE Objects ("
  "objectID INTEGER PRIMARY KEY,"
  "pin TEXT DEFAULT NULL);";

static char sqlCreateTableAttributes[] =
  "CREATE TABLE Attributes ("
  "attributeID INTEGER PRIMARY KEY,"
  "objectID INTEGER DEFAULT NULL,"
  "type INTEGER DEFAULT NULL,"
  "value BLOB DEFAULT NULL,"
  "length INTEGER DEFAULT 0);";

static char sqlDeleteTrigger[] = 
  "CREATE TRIGGER deleteTrigger BEFORE DELETE ON Objects "
  "BEGIN "
    "DELETE FROM Attributes "
      "WHERE objectID = OLD.objectID; "
  "END;";

SoftDatabase::SoftDatabase() {
  char *sqlError;

  // Open the database
  int result = sqlite3_open(getDatabasePath(), &db);
  if(result){
    fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    exit(1);
  }

  // Check that the Objects table exist
  result = sqlite3_exec(db, "SELECT COUNT(objectID) FROM Objects;", NULL, NULL, NULL);
  if(result) {
    result = sqlite3_exec(db, sqlCreateTableObjects, NULL, NULL, &sqlError);
    if(result) {
      fprintf(stderr, "Can't create table Objects: %s\n", sqlError);
      sqlite3_close(db);
      exit(1);
    }
  }

  // Check that the Attributes table exist
  result = sqlite3_exec(db, "SELECT COUNT(attributeID) FROM Attributes;", NULL, NULL, NULL);
  if(result) {
    result = sqlite3_exec(db, sqlCreateTableAttributes, NULL, NULL, &sqlError);
    if(result) {
      fprintf(stderr, "Can't create table Attributes: %s\n", sqlError);
      sqlite3_close(db);
      exit(1);
    }
    sqlite3_exec(db, sqlDeleteTrigger, NULL, NULL, NULL);
  }
}

SoftDatabase::~SoftDatabase() {
  sqlite3_close(db);
}

// Save the public RSA key in the database.

int SoftDatabase::addRSAKeyPub(char *pin, RSA_PrivateKey *rsaKey, CK_ATTRIBUTE_PTR pPublicKeyTemplate, 
    CK_ULONG ulPublicKeyAttributeCount, char *labelID) {

  stringstream sqlInsertObj;

  sqlInsertObj << "INSERT INTO Objects (pin) VALUES ('" << pin << "');";
  int result = sqlite3_exec(db, sqlInsertObj.str().c_str(), NULL, NULL, NULL);

  if(result) {
    return 0;
  }

  int objectID = sqlite3_last_insert_rowid(db);

  CK_OBJECT_CLASS oClass = CKO_PUBLIC_KEY;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_MECHANISM_TYPE mechType = CKM_RSA_PKCS_KEY_PAIR_GEN;
  CK_BBOOL ckTrue = CK_TRUE;

  // General information
  this->saveAttribute(objectID, CKA_CLASS, &oClass, sizeof(oClass));
  this->saveAttribute(objectID, CKA_KEY_TYPE, &keyType, sizeof(keyType));
  this->saveAttribute(objectID, CKA_KEY_GEN_MECHANISM, &mechType, sizeof(mechType));
  this->saveAttribute(objectID, CKA_LOCAL, &ckTrue, sizeof(ckTrue));

  // The RSA modulus bits
  IF_Scheme_PublicKey *ifKey = dynamic_cast<IF_Scheme_PublicKey*>(rsaKey);
  BigInt bigModulus = ifKey->get_n();
  CK_ULONG bits = bigModulus.bits();
  this->saveAttribute(objectID, CKA_MODULUS_BITS, &bits, sizeof(bits));

  // The RSA modulus
  this->saveAttributeBigInt(objectID, CKA_MODULUS, &bigModulus);

  // The RSA public exponent
  BigInt bigExponent = ifKey->get_e();
  this->saveAttributeBigInt(objectID, CKA_PUBLIC_EXPONENT, &bigExponent);

  int foundLabel = 0, foundID = 0;

  // Extract the attributes
  for(CK_ULONG i = 0; i < ulPublicKeyAttributeCount; i++) {
    switch(pPublicKeyTemplate[i].type) {
      case CKA_LABEL:
        foundLabel = 1;
        this->saveAttribute(objectID, CKA_LABEL, pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
        break;
      case CKA_ID:
        foundID = 1;
        this->saveAttribute(objectID, CKA_ID, pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
        break;
      case CKA_DERIVE:
      case CKA_TOKEN:
      case CKA_PRIVATE:
      case CKA_MODIFIABLE:
      case CKA_SUBJECT:
      case CKA_ENCRYPT:
      case CKA_VERIFY:
      case CKA_VERIFY_RECOVER:
      case CKA_WRAP:
      case CKA_TRUSTED:
        this->saveAttribute(objectID, pPublicKeyTemplate[i].type, pPublicKeyTemplate[i].pValue, pPublicKeyTemplate[i].ulValueLen);
        break;
      default:
        break;
    }
  }

  // Assign a default value if not defined by the user.
  if(foundLabel == 0) {
    this->saveAttribute(objectID, CKA_LABEL, labelID, strlen(labelID));
  }
  if(foundID == 0) {
    this->saveAttribute(objectID, CKA_ID, labelID, strlen(labelID));
  }

  return objectID;
}

// Save the private RSA key in the database.

int SoftDatabase::addRSAKeyPriv(char *pin, RSA_PrivateKey *rsaKey, CK_ATTRIBUTE_PTR pPrivateKeyTemplate, 
    CK_ULONG ulPrivateKeyAttributeCount, char *labelID) {

  stringstream sqlInsertObj;

  sqlInsertObj << "INSERT INTO Objects (pin) VALUES ('" << pin << "');";
  int result = sqlite3_exec(db, sqlInsertObj.str().c_str(), NULL, NULL, NULL);

  if(result) {
    return 0;
  }

  int objectID = sqlite3_last_insert_rowid(db);

  CK_OBJECT_CLASS oClass = CKO_PRIVATE_KEY;
  CK_KEY_TYPE keyType = CKK_RSA;
  CK_MECHANISM_TYPE mechType = CKM_RSA_PKCS_KEY_PAIR_GEN;
  CK_BBOOL ckTrue = CK_TRUE;

  // General information
  this->saveAttribute(objectID, CKA_CLASS, &oClass, sizeof(oClass));
  this->saveAttribute(objectID, CKA_KEY_TYPE, &keyType, sizeof(keyType));
  this->saveAttribute(objectID, CKA_KEY_GEN_MECHANISM, &mechType, sizeof(mechType));
  this->saveAttribute(objectID, CKA_LOCAL, &ckTrue, sizeof(ckTrue));

  // The RSA modulus bits
  IF_Scheme_PrivateKey *ifKeyPriv = dynamic_cast<IF_Scheme_PrivateKey*>(rsaKey);
  BigInt bigNumber = ifKeyPriv->get_n();
  CK_ULONG bits = bigNumber.bits();
  this->saveAttribute(objectID, CKA_MODULUS_BITS, &bits, sizeof(bits));

  // The RSA modulus
  this->saveAttributeBigInt(objectID, CKA_MODULUS, &bigNumber);

  // The RSA public exponent
  bigNumber = ifKeyPriv->get_e();
  this->saveAttributeBigInt(objectID, CKA_PUBLIC_EXPONENT, &bigNumber);

  // The RSA private exponent
  bigNumber = ifKeyPriv->get_d();
  this->saveAttributeBigInt(objectID, CKA_PRIVATE_EXPONENT, &bigNumber);

  // The RSA prime p
  bigNumber = ifKeyPriv->get_p();
  this->saveAttributeBigInt(objectID, CKA_PRIME_1, &bigNumber);

  // The RSA prime q
  bigNumber = ifKeyPriv->get_q();
  this->saveAttributeBigInt(objectID, CKA_PRIME_2, &bigNumber);

  int foundLabel = 0, foundID = 0;

  // Extract the attributes
  for(CK_ULONG i = 0; i < ulPrivateKeyAttributeCount; i++) {
    switch(pPrivateKeyTemplate[i].type) {
      case CKA_LABEL:
        foundLabel = 1;
        this->saveAttribute(objectID, CKA_LABEL, pPrivateKeyTemplate[i].pValue, pPrivateKeyTemplate[i].ulValueLen);
        break;
      case CKA_ID:
        foundID = 1;
        this->saveAttribute(objectID, CKA_ID, pPrivateKeyTemplate[i].pValue, pPrivateKeyTemplate[i].ulValueLen);
        break;
      case CKA_DERIVE:
      case CKA_TOKEN:
      case CKA_PRIVATE:
      case CKA_MODIFIABLE:
      case CKA_SUBJECT:
      case CKA_SENSITIVE:
      case CKA_DECRYPT:
      case CKA_SIGN:
      case CKA_SIGN_RECOVER:
      case CKA_UNWRAP:
      case CKA_EXTRACTABLE:
      case CKA_ALWAYS_SENSITIVE:
      case CKA_NEVER_EXTRACTABLE:
      case CKA_WRAP_WITH_TRUSTED:
      case CKA_ALWAYS_AUTHENTICATE:
        this->saveAttribute(objectID, pPrivateKeyTemplate[i].type, pPrivateKeyTemplate[i].pValue, pPrivateKeyTemplate[i].ulValueLen);
        break;
      default:
        break;
    }
  }

  // Assign a default value if not defined by the user.
  if(foundLabel == 0) {
    this->saveAttribute(objectID, CKA_LABEL, labelID, strlen(labelID));
  }
  if(foundID == 0) {
    this->saveAttribute(objectID, CKA_ID, labelID, strlen(labelID));
  }

  return objectID;
}

// Save the attribute in the database.

void SoftDatabase::saveAttribute(int objectID, CK_ATTRIBUTE_TYPE type, CK_VOID_PTR pValue, CK_ULONG ulValueLen) {
  string sqlInsert = "INSERT INTO Attributes (objectID, type, value, length) VALUES (?, ?, ?, ?);";

  sqlite3_stmt *insert_sql;
  int result = sqlite3_prepare_v2(db, sqlInsert.c_str(), sqlInsert.size(), &insert_sql, NULL);

  if(result) {
    return;
  }

  sqlite3_bind_int(insert_sql, 1, objectID);
  sqlite3_bind_int(insert_sql, 2, type);
  sqlite3_bind_blob(insert_sql, 3, pValue, ulValueLen, SQLITE_TRANSIENT);
  sqlite3_bind_int(insert_sql, 4, ulValueLen);

  sqlite3_step(insert_sql);
  sqlite3_finalize(insert_sql);
}

// Convert the big integer and save it in the database.

void SoftDatabase::saveAttributeBigInt(int objectID, CK_ATTRIBUTE_TYPE type, BigInt *bigNumber) {
  unsigned int size = bigNumber->bytes();
  char *buf = (char *)malloc(size);
  
  bigNumber->binary_encode((byte *)buf);

  this->saveAttribute(objectID, type, buf, size);
  free(buf);
}

// Creates an object an populate it with attributes from the database.

void SoftDatabase::populateObj(SoftObject *&keyObject, int keyRef) {
  stringstream sqlQuery;
  sqlQuery << "SELECT type,value,length from Attributes WHERE objectID = " << keyRef << ";";

  string sqlQueryStr = sqlQuery.str();
  sqlite3_stmt *select_sql;
  int result = sqlite3_prepare(db, sqlQueryStr.c_str(), sqlQueryStr.size(), &select_sql, NULL);

  if(result) {
    return;
  }

  keyObject = new SoftObject();
  keyObject->index = keyRef;


  BigInt modulus(0);
  BigInt pubExp(0);
  BigInt privExp(0);
  BigInt prime1(0);
  BigInt prime2(0);
  CK_ULONG tmpValue;

  // Add all attributes
  while(sqlite3_step(select_sql) == SQLITE_ROW) {
    CK_ATTRIBUTE_TYPE type = sqlite3_column_int(select_sql, 0);
    CK_VOID_PTR pValue = (CK_VOID_PTR)sqlite3_column_blob(select_sql, 1);
    int length = sqlite3_column_int(select_sql, 2);

    keyObject->addAttributeFromData(type, pValue, length);

    switch(type) {
      case CKA_CLASS:
        keyObject->objectClass = *(CK_OBJECT_CLASS *)pValue;
        break;
      case CKA_KEY_TYPE:
        keyObject->keyType = *(CK_KEY_TYPE *)pValue;
        break;
      case CKA_SENSITIVE:
        keyObject->sensible = *(CK_BBOOL *)pValue;
        break;
      case CKA_EXTRACTABLE:
        keyObject->extractable = *(CK_BBOOL *)pValue;
        break;
      case CKA_MODULUS_BITS:
        tmpValue = *(CK_ULONG *)pValue;
        keyObject->keySizeBytes = (tmpValue + 7) / 8;
        break;
      case CKA_MODULUS:
        modulus.binary_decode((byte *)pValue, length);
        break;
      case CKA_PUBLIC_EXPONENT:
        pubExp.binary_decode((byte *)pValue, length);
        break;
      case CKA_PRIVATE_EXPONENT:
        privExp.binary_decode((byte *)pValue, length);
        break;
      case CKA_PRIME_1:
        prime1.binary_decode((byte *)pValue, length);
        break;
      case CKA_PRIME_2:
        prime2.binary_decode((byte *)pValue, length);
        break;
    }
  }

  sqlite3_finalize(select_sql);

  if(keyObject->objectClass == CKO_PUBLIC_KEY && keyObject->keyType == CKK_RSA) {
    if(modulus.is_zero() || pubExp.is_zero()) {
      delete keyObject;
      keyObject = NULL_PTR;
    }
    keyObject->key = new RSA_PublicKey(modulus, pubExp);
  }
  if(keyObject->objectClass == CKO_PRIVATE_KEY && keyObject->keyType == CKK_RSA) {
    if(prime1.is_zero() || prime2.is_zero() || pubExp.is_zero() || 
       privExp.is_zero() || modulus.is_zero()) {
      delete keyObject;
      keyObject = NULL_PTR;
    }

    AutoSeeded_RNG *rng = new AutoSeeded_RNG();
    keyObject->key = new RSA_PrivateKey(*rng, prime1, prime2, pubExp, privExp, modulus);
  }
}

// Delete an object and its attributes, if the PIN is correct.
// The trigger in the database removes the attributes.

void SoftDatabase::deleteObject(char *pin, int objRef) {
  stringstream sqlDeleteObj;

  sqlDeleteObj << "DELETE FROM Objects WHERE pin = '" << pin << "' and objectID = " 
               << objRef << ";";
  sqlite3_exec(db, sqlDeleteObj.str().c_str(),  NULL, NULL, NULL);
}

// Returns the object IDs for a given PIN

int* SoftDatabase::getObjectRefs(char *pin, int &objectCount) {
  objectCount = 0;

  // Find out how many objects we have.
  string sqlCount = "SELECT COUNT(objectID) FROM Objects WHERE pin = ?;";
  sqlite3_stmt *count_sql;
  int result = sqlite3_prepare_v2(db, sqlCount.c_str(), sqlCount.size(), &count_sql, NULL);

  // Error?
  if(result != 0) {
    return NULL_PTR;
  }

  // Supply the PIN to the query
  sqlite3_bind_text(count_sql, 1, pin, strlen(pin), SQLITE_TRANSIENT);

  // Get the result from the query
  if(sqlite3_step(count_sql) != SQLITE_ROW) {
    return NULL_PTR;
  }

  // Return the number of objects
  objectCount = sqlite3_column_int(count_sql, 0);
  sqlite3_finalize(count_sql);

  // Create the object-reference buffer
  int *objectRefs = (int *)malloc(objectCount * sizeof(int));

  // Get all the objects
  string sqlSelect = "SELECT objectID FROM Objects WHERE pin = ? ORDER BY objectID ASC;";
  sqlite3_stmt *select_sql;
  result = sqlite3_prepare_v2(db, sqlSelect.c_str(), sqlSelect.size(), &select_sql, NULL);

  // Error?
  if(result != 0) {
    return NULL_PTR;
  }

  // Supply the PIN to the query
  sqlite3_bind_text(select_sql, 1, pin, strlen(pin), SQLITE_TRANSIENT);

  // Get the results  
  int tmpCounter = 0;
  while(sqlite3_step(select_sql) == SQLITE_ROW && tmpCounter < objectCount) {
    objectRefs[tmpCounter++] = sqlite3_column_int(select_sql, 0);
  }

  sqlite3_finalize(select_sql);
 
  return objectRefs;
}