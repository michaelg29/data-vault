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

int dv_createEntryData(dv_app *dv, const char *name, const char *category, const char *data)
{
    if (!dv->loggedIn)
    {
        return DV_LOGGED_OUT;
    }

    // find entry id
    unsigned int entryId = (unsigned int)avl_get(dv->nameIdMap, (void *)name);
    if (!entryId)
    {
        // create entry
        dv_createEntry(dv, name);
        entryId = dv->maxEntryId;
    }

    // find the category id
    unsigned char catId = (unsigned char)(unsigned int)avl_get(dv->catIdMap, (void *)category);
    if (!catId)
    {
        // create category
        catId = ++dv->maxCatId;
        char *catCopy = malloc(strlen(category) + 1);
        memcpy(catCopy, category, strlen(category) + 1);
        dv->catIdMap = avl_insert(dv->catIdMap, (void *)catCopy, (void *)(unsigned int)catId);
    }

    // cursor over input
    int dataCursor = -1;
    int dataLen = strlen(data) + 1;

    // block cursors
    unsigned int previousBlock = 1;
    unsigned int currentBlock = (unsigned int)btree_search(dv->idIdxMap, entryId);
    unsigned int nextBlock = 1;

    if (DV_DEBUG)
    {
        printf("Entry id for %s: %d\n", name, entryId);
        printf("Category id for %s: %d\n", category, catId);
        printf("Insert data (%d): %s\n", dataLen, data);
        printHexString(data, dataLen, "data");
    }

    // write the data
    file_struct dataFile;
    file_struct dataOut;
    if (file_open(&dataFile, data_fp, "rb") &&
        file_open(&dataOut, data_tmp_fp, "wb"))
    {
        // set up files to be read/written
        file_setBlockSize(&dataFile, 16);
        file_setBlockSize(&dataOut, 16);
        unsigned int noBlocks = dataFile.len >> 4; // len / 16

        // copy first block
        char *copy = file_readBlocks(&dataFile, 1);
        file_writeBlocks(&dataOut, copy, 1);
        free(copy);

        // setup initialization vector
        unsigned char *ivCopy = malloc(16);
        memcpy(ivCopy, dv->random + dataIV_offset, 16);

        // iterate through input
        while (dataCursor < dataLen)
        {
            if (DV_DEBUG)
            {
                printf("==Block %d\n", currentBlock);
            }

            // determine increment and skip blocks
            int increment = currentBlock - previousBlock;
            if (currentBlock <= noBlocks && increment)
            {
                // content to copy (skipped)
                copy = file_readBlocks(&dataFile, increment);
                file_writeBlocks(&dataOut, copy, increment);
                free(copy);
            }
            aes_incrementCounter(ivCopy, increment + 1);

            char *enc;
            unsigned char *dec = NULL;
            unsigned int startIdx;
            if (currentBlock < noBlocks)
            {
                // read and decrypt existing block
                enc = file_readBlocks(&dataFile, 1);
                aes_decrypt_withSchedule(enc, 16, dv->aes_key_schedule, AES_256_NR, AES_CTR, ivCopy, &dec);

                if (DV_DEBUG)
                {
                    printHexString(enc, 16, "encBlk");
                    printHexString(dec, 16, "decBlk");
                }

                // find continuation block
                nextBlock = smallEndianValue(dec + 12, 4);
                if (nextBlock)
                {
                    // data ends in another block, cannot write to this one

                    // update counters
                    previousBlock = currentBlock + 1;
                    currentBlock = nextBlock;

                    // write unmodified data
                    file_writeBlocks(&dataOut, enc, 1);

                    if (DV_DEBUG)
                    {
                        printf("nonMod\n");
                    }

                    free(dec);
                    free(enc);

                    continue;
                }

                // find first available character
                int i = 16 - sizeof(unsigned int) - 1;
                while (i >= 0 && dec[i])
                {
                    i--;
                }

                // start writing after 0
                startIdx = i + 1;

                // additional data written at end of file
                nextBlock = noBlocks;
            }
            else
            {
                // create new block
                dec = malloc(16);
                memset(dec, 0x22, 16 - sizeof(unsigned int)); // arbitrary value
                memset(dec + 12, 0, sizeof(unsigned int));    // continuation block

                // start writing on first byte
                startIdx = 0;

                // additional data written immediately after
                nextBlock = currentBlock + 1;
            }

            bool modified = false;
            if (dataCursor == -1 && startIdx < 16 - sizeof(unsigned int))
            {
                // write category id
                dec[startIdx] = catId;
                modified = true;

                // write data after category id
                startIdx++;
                dataCursor = 0;
            }

            if (startIdx < 16 - sizeof(unsigned int))
            {
                // write as much data as possible
                int n = MIN(16 - sizeof(unsigned int) - startIdx,
                            dataLen - dataCursor);
                if (n)
                {
                    memcpy(dec + startIdx, data + dataCursor, n);
                    dataCursor += n;
                    modified = true;
                }
            }

            if (dataCursor < dataLen)
            {
                // more data to write
                smallEndianStr(nextBlock, dec + 12, 4);
                modified = true;
            }

            // update counters
            previousBlock = currentBlock + 1;
            currentBlock = nextBlock;

            if (modified)
            {
                free(enc);
                aes_encrypt_withSchedule(dec, 16,
                                         dv->aes_key_schedule, AES_256_NR, AES_CTR,
                                         ivCopy,
                                         (unsigned char **)&enc);
                file_writeBlocks(&dataOut, enc, 1);

                if (DV_DEBUG)
                {
                    printHexString(dec, 16, "modBlk");
                    printHexString(enc, 16, "encMod");
                }
            }

            free(enc);
            free(dec);
        }

        free(ivCopy);

        // close files
        file_close(&dataOut);
        file_close(&dataFile);

        // copy contents to main data file
        file_open(&dataFile, data_fp, "wb");
        file_open(&dataOut, data_tmp_fp, "rb");

        char *in = file_read(&dataOut, dataOut.len);
        file_write(&dataFile, in, dataOut.len);

        file_close(&dataFile);
        file_close(&dataOut);

        free(in);
    }
    else
    {
        file_close(&dataFile);
        file_close(&dataOut);
        return DV_FILE_DNE;
    }

    return DV_SUCCESS;
}