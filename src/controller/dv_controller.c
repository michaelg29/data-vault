#include "dv_controller.h"

#include "../datavault.h"
#include "dv_persistence.h"

#include "../lib/cmathematics/util/numio.h"
#include "../lib/cmathematics/data/encryption/aes.h"
#include "../lib/cmathematics/data/hashing/sha.h"
#include "../lib/cmathematics/data/hashing/sha3.h"
#include "../lib/cmathematics/data/hashing/pbkdf.h"
#include "../lib/cmathematics/lib/arrays.h"

#include "../lib/util/fileio.h"
#include "../lib/util/mem.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

const unsigned int userPwdSalt_offset = 0x00;
const unsigned int kekSalt_offset = 0x10;
const unsigned int dataKeyIV_offset = 0x20;
const unsigned int dataIV_offset = 0x30;
const unsigned int nameIdIV_offset = 0x40;
const unsigned int idIdxIV_offset = 0x50;
const unsigned int catIdIV_offset = 0x60;

int dv_createAccount(dv_app *dv, unsigned char *userPwd, int n)
{
    // input validation
    if (!n || !userPwd)
    {
        return DV_INVALID_INPUT;
    }

    int retCode = DV_SUCCESS;

    unsigned char *random = NULL;
    sha3_context hashCtx;
    unsigned char *hash = NULL;
    unsigned char *dataKey = NULL;
    unsigned char *kek = NULL;
    unsigned char *encDataKey = NULL;

    do
    {
        // generate salts and IVs
        if (!(random = newRandomBytes(0x70)))
        {
            retCode = DV_MEM_ERR;
            break;
        }
        if (retCode = dv_initFiles(random))
        {
            break;
        }

        /**
         * HASH userPwd
         */
        // generate hash
        sha3_initContext(&hashCtx, SHA3_512);
        sha3_update(&hashCtx, userPwd, n);
        sha3_update(&hashCtx, random + userPwdSalt_offset, 16); // update with salt
        sha3_digest(&hashCtx, &hash);

        // write to file
        if (!file_writeContents(pwd_fp, hash, hashCtx.ret_len))
        {
            retCode = DV_FILE_DNE;
            break;
        }

        /**
         * DATA KEY
         */
        // generate
        dataKey = newRandomBytes(DV_KEYLEN);
        pbkdf2_hmac_sha(userPwd, n,
                        random + kekSalt_offset, 16,
                        10, SHA512_STR, DV_KEYLEN, &kek);

        // encrypt key
        aes_encrypt(dataKey, 16,
                    kek, AES_256, AES_CTR,
                    random + dataKeyIV_offset,
                    &encDataKey);

        // write encrypted data key
        if (!file_writeContents(dk_fp, encDataKey, DV_KEYLEN))
        {
            retCode = DV_FILE_DNE;
            break;
        }

        if (DV_DEBUG)
        {
            printHexString(userPwd, n, "userPwd");
            printHexString(random + userPwdSalt_offset, 16, "userPwdSalt");
            printHexString(hash, hashCtx.ret_len, "userPwdHash");
            printHexString(dataKey, DV_KEYLEN, "dataKey");
            printHexString(random + kekSalt_offset, 16, "kekSalt");
            printHexString(kek, DV_KEYLEN, "kek");
            printHexString(random + dataKeyIV_offset, 16, "dataKeyIV");
            printHexString(encDataKey, DV_KEYLEN, "encDataKey");
        }
    } while (false);

    conditionalFree(random, free);
    conditionalFree(hash, free);
    conditionalFree(dataKey, free);
    conditionalFree(kek, free);
    conditionalFree(encDataKey, free);

    return retCode;
}

int dv_login(dv_app *dv, unsigned char *userPwd, int n)
{
    int retCode = DV_SUCCESS;

    sha3_context hashCtx;
    unsigned char *hash = NULL;
    char *expected = NULL;
    unsigned char *kek;
    char *encDataKey = NULL;
    unsigned char *tmp;

    do
    {
        // initialize memory
        dv_init(dv);

        // read salts/ivs
        if (!(dv->random = file_readContents(iv_fp)))
        {
            retCode = DV_FILE_DNE;
            break;
        }

        /**
         * VALIDATE INPUT PASSWORD
         */
        // generate input hash
        sha3_initContext(&hashCtx, SHA3_512);
        sha3_update(&hashCtx, userPwd, n);
        sha3_update(&hashCtx, dv->random + userPwdSalt_offset, 16); // concatenate salt
        sha3_digest(&hashCtx, &hash);

        // read expected value
        file_struct pwdFile;
        if (file_open(&pwdFile, pwd_fp, "rb"))
        {
            // read file
            expected = file_read(&pwdFile, hashCtx.ret_len);

            // compare
            if (memcmp(hash, expected, hashCtx.ret_len))
            {
                dv_kill(dv);
                retCode = DV_INVALID_INPUT;
                break;
            }
            // else succeeded

            file_close(&pwdFile);
        }
        else
        {
            retCode = DV_FILE_DNE;
            break;
        }

        /**
         * DATA KEY
         */
        // derive key encryption key
        pbkdf2_hmac_sha(userPwd, n,
                        dv->random + kekSalt_offset, 16,
                        10, SHA512_STR, DV_KEYLEN, &kek);

        if (!(encDataKey = file_readContents(dk_fp)))
        {
            retCode = DV_FILE_DNE;
            break;
        }

        // decrypt
        aes_decrypt(encDataKey, DV_KEYLEN,
                    kek, AES_256, AES_CTR,
                    dv->random + dataKeyIV_offset, &tmp);
        memcpy(dv->dataKey, tmp, DV_KEYLEN);

        // generate AES key schedule
        aes_generateKeySchedule(dv->dataKey, AES_256, dv->aes_key_schedule);

        // call the load sequence
        retCode = dv_load(dv);

        if (DV_DEBUG)
        {
            printHexString(userPwd, n, "userPwd");
            printHexString(dv->random + userPwdSalt_offset, 16, "userPwdSalt");
            printHexString(hash, hashCtx.ret_len, "userPwdHash");
            printHexString(expected, hashCtx.ret_len, "expectedHash");
            printHexString(dv->random + kekSalt_offset, 16, "kekSalt");
            printHexString(kek, DV_KEYLEN, "kek");
            printHexString(encDataKey, DV_KEYLEN, "encDataKey");
            printHexString(dv->random + dataKeyIV_offset, 16, "dataKeyIV");
            printHexString(dv->dataKey, DV_KEYLEN, "decDataKey");
        }
    } while (false);

    conditionalFree(hash, free);
    conditionalFree(expected, free);
    conditionalFree(kek, free);
    conditionalFree(encDataKey, free);
    conditionalFree(tmp, free);

    if (retCode)
    {
        dv_kill(dv);
    }
    else
    {
        dv->loggedIn = true;
    }

    return retCode;
}

int dv_logout(dv_app *dv)
{
    int retCode = DV_SUCCESS;

    do
    {
        if (retCode = dv_save(dv))
        {
            break;
        }

        dv_kill(dv);
    } while (false);

    return DV_SUCCESS;
}

int dv_createEntry(dv_app *dv, const char *name)
{
    if (!dv->loggedIn)
    {
        return DV_LOGGED_OUT;
    }

    if (avl_get(dv->nameIdMap, (void *)name))
    {
        // entry already exists
        return DV_INVALID_INPUT;
    }

    // make copy
    int len = strlen(name);
    char *nameCopy = malloc(len + 1);
    strcpy(nameCopy, name);
    nameCopy[len] = 0;

    // insert copy into name map
    dv->nameIdMap = avl_insert(dv->nameIdMap,
                               nameCopy,
                               (void *)(++dv->maxEntryId));

    // create block
    file_struct dataFile;
    if (file_open(&dataFile, data_fp, "ab"))
    {
        // setup file
        file_setBlockSize(&dataFile, 16);
        // find end of file
        int initBlock = dataFile.len >> 4; // len / 16

        // populate block: 0x22 * 12, smallEndian(0)
        unsigned char *emptyBlock = malloc(16);
        memset(emptyBlock, 0x22, 12);
        memset(emptyBlock + 12, 0, 4);

        // increment counter
        unsigned char *ivCopy = malloc(16);
        memcpy(ivCopy, dv->random + dataIV_offset, 16);
        aes_incrementCounter(ivCopy, initBlock);

        // encrypt
        unsigned char *enc;
        aes_encrypt_withSchedule(emptyBlock, 16,
                                 dv->aes_key_schedule, AES_256_NR,
                                 AES_CTR,
                                 ivCopy,
                                 &enc);

        // append to file
        file_writeBlocks(&dataFile, enc, 1);

        // insert into index map
        btree_insert(&dv->idIdxMap, dv->maxEntryId, (void *)initBlock);

        if (DV_DEBUG)
        {
            printf("entryId: %d\n", dv->maxEntryId);
            printf("blockIdx: %d\n", initBlock);
            printHexString(emptyBlock, 16, "block");
            printHexString(ivCopy, 16, "ivInc");
            printHexString(enc, 16, "encBlock");
        }

        // free variables
        free(emptyBlock);
        free(ivCopy);
        free(enc);

        // close file
        file_close(&dataFile);
    }
    else
    {
        return DV_FILE_DNE;
    }

    return DV_SUCCESS;
}