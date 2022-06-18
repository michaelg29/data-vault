#include "dv_controller.h"

#include "../datavault.h"
#include "dv_persistence.h"

#include "../lib/cmathematics/util/numio.h"
#include "../lib/cmathematics/data/encryption/aes.h"
#include "../lib/cmathematics/data/hashing/sha.h"
#include "../lib/cmathematics/data/hashing/sha3.h"
#include "../lib/cmathematics/data/hashing/pbkdf.h"
#include "../lib/cmathematics/lib/arrays.h"

#include "../lib/ds/dynamicarray.h"
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

// shortcut for encryption/decryption calls
#define AES_ENC_BLK(dv, in, iv, out) aes_encrypt_withSchedule(in, 16, dv->aes_key_schedule, AES_256_NR, AES_CTR, iv, out)
#define AES_DEC_BLK(dv, in, iv, out) aes_decrypt_withSchedule(in, 16, dv->aes_key_schedule, AES_256_NR, AES_CTR, iv, out)

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
        aes_encrypt(dataKey, DV_KEYLEN,
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
    if (file_openBlocks(&dataFile, data_fp, "ab", 16))
    {
        // find end of file
        int initBlock = dataFile.len >> 4; // len / 16

        // populate block: 0x22 * 12, smallEndian(0)
        unsigned char *emptyBlock = malloc(16);
        memset(emptyBlock, 0x22, 14);
        memset(emptyBlock + 14, 0, 2);

        // increment counter
        unsigned char *ivCopy = malloc(16);
        memcpy(ivCopy, dv->random + dataIV_offset, 16);
        aes_incrementCounter(ivCopy, initBlock);

        // encrypt
        unsigned char *enc;
        AES_ENC_BLK(dv, emptyBlock, ivCopy, &enc);

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
        printHexString((char*)data, dataLen, "data");
    }

    // write the data
    file_struct dataFile;
    file_struct dataOut;
    if (file_openBlocks(&dataFile, data_fp, "rb", 16) &&
        file_openBlocks(&dataOut, data_tmp_fp, "wb", 16))
    {
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
                AES_DEC_BLK(dv, enc, ivCopy, &dec);

                if (DV_DEBUG)
                {
                    printHexString(enc, 16, "encBlk");
                    printHexString(dec, 16, "decBlk");
                }

                // find continuation block
                nextBlock = smallEndianValue(dec + 14, 2);
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
                int i = 16 - sizeof(unsigned short) - 1;
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
                memset(dec, 0x22, 16 - sizeof(unsigned short)); // arbitrary value
                memset(dec + 14, 0, sizeof(unsigned short));    // continuation block

                // start writing on first byte
                startIdx = 0;

                // additional data written immediately after
                nextBlock = currentBlock + 1;
            }

            bool modified = false;
            if (dataCursor == -1 && startIdx < 16 - sizeof(unsigned short))
            {
                // write category id
                dec[startIdx] = catId;
                modified = true;

                // write data after category id
                startIdx++;
                dataCursor = 0;
            }

            if (startIdx < 16 - sizeof(unsigned short))
            {
                // write as much data as possible
                int n = MIN(16 - sizeof(unsigned short) - startIdx,
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
                smallEndianStr(nextBlock, dec + 14, 2);
                modified = true;
            }

            // update counters
            previousBlock = currentBlock + 1;
            currentBlock = nextBlock;

            if (modified)
            {
                free(enc);
                AES_ENC_BLK(dv, dec, ivCopy, (unsigned char **)&enc);
                file_writeBlocks(&dataOut, enc, 1);

                if (DV_DEBUG)
                {
                    printHexString(ivCopy, 16, "iv");
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

        file_copy(data_fp, data_tmp_fp);
    }
    else
    {
        file_close(&dataFile);
        file_close(&dataOut);
        return DV_FILE_DNE;
    }

    return DV_SUCCESS;
}

int dv_deleteEntryData(dv_app *dv, const char *name, const char *category)
{
    if (!dv->loggedIn)
    {
        return DV_LOGGED_OUT;
    }

    // find entry id
    unsigned int entryId = (unsigned int)avl_get(dv->nameIdMap, (void *)name);
    if (!entryId)
    {
        return DV_INVALID_INPUT;
    }

    // find the category id
    unsigned char catId = (unsigned char)(unsigned int)avl_get(dv->catIdMap, (void *)category);
    if (!catId)
    {
        return DV_INVALID_INPUT;
    }

    // block cursors
    unsigned int previousBlock = 1;
    unsigned int currentBlock = (unsigned int)btree_search(dv->idIdxMap, entryId);
    unsigned int nextBlock = 1;

    if (DV_DEBUG)
    {
        printf("Entry id for %s: %d\n", name, entryId);
        printf("Category id for %s: %d\n", category, catId);
    }

    strstream entryData = strstream_allocDefault();
    dynamicarray occupiedBlocks = dynarr_defaultAllocate();

    unsigned char *ivCopy = NULL;
    unsigned char *ivCopyIn = NULL;
    unsigned char *ivCopyOut = NULL;

    char *enc = NULL;
    unsigned char *dec = NULL;
    
    int retCode = DV_SUCCESS;

    do
    {
        file_struct dataFile;
        if (!file_openBlocks(&dataFile, data_fp, "rb", 16))
        {
            retCode = DV_FILE_DNE;
            break;
        }
        unsigned int noBlocks = dataFile.len >> 4; // len / 16

        // skip first block
        file_advanceCursorBlocks(&dataFile, 1);

        // copy IV
        ivCopy = malloc(16);
        memcpy(ivCopy, dv->random + dataIV_offset, 16);

        bool onTarget = false;
        bool scanData = false;
        bool complete = false;
        unsigned int startIdx;

        while (currentBlock < noBlocks)
        {
            dynarr_addLast(&occupiedBlocks, (void*)currentBlock);

            // skip blocks
            int increment = currentBlock - previousBlock;
            file_advanceCursorBlocks(&dataFile, increment);
            aes_incrementCounter(ivCopy, increment + 1);

            // read block
            enc = file_readBlocks(&dataFile, 1);
            AES_DEC_BLK(dv, enc, ivCopy, &dec);
            // read continuation block
            nextBlock = smallEndianValue(dec + 14, 2);

            if (DV_DEBUG)
            {
                printf("==Block %d: increment by %d\n", currentBlock, increment);
                printHexString(enc, 16, "encBlock");
                printHexString(ivCopy, 16, "ivInc");
                printHexString(dec, 16, "decBlock");
            }

            if (complete)
            {
                int endIdx = 16 - sizeof(short);
                while (!nextBlock && dec[endIdx - 1]) endIdx--;
                strstream_read(&entryData, dec, endIdx - startIdx);
            }
            else
            {
                for (int i = 0; i < 14; i++)
                {
                    if (!scanData)
                    {
                        scanData = true;

                        if (dec[i] == catId)
                        {
                            // found target
                            onTarget = true;
                            startIdx = 16;

                            // read into data stream until entry
                            if (i)
                            {
                                strstream_read(&entryData, dec, i);
                            }
                        }
                    }

                    if (!dec[i])
                    {
                        // terminator character
                        scanData = false;

                        if (onTarget)
                        {
                            // finished reading target
                            startIdx = i + 1;
                            complete = true;
                            break;
                        }
                    }
                }

                // read after block
                if (!complete && startIdx >= 0 && startIdx < 16 - sizeof(short))
                {
                    int endIdx = 16 - sizeof(short);
                    while (!nextBlock && dec[endIdx - 1]) endIdx--;
                    strstream_read(&entryData, dec + startIdx, endIdx - startIdx);
                }
            }

            

            free(enc);
            free(dec);

            if (!nextBlock)
            {
                // read all data
                break;
            }

            // update counters
            previousBlock = currentBlock + 1;
            currentBlock = nextBlock;
        }
        if (currentBlock != noBlocks - 1)
        {
            dynarr_addLast(&occupiedBlocks, (void*)noBlocks);
        }

        file_close(&dataFile);
        free(ivCopy);

        if (!(complete && onTarget))
        {
            // not found
            retCode = DV_INVALID_INPUT;
            break;
        }

        // write to file
        file_struct dataIn;
        if (!file_openBlocks(&dataIn, data_fp, "rb", 16))
        {
            retCode = DV_FILE_DNE;
            break;
        }

        file_struct dataOut;
        if (!file_openBlocks(&dataOut, data_tmp_fp, "wb", 16))
        {
            retCode = DV_FILE_DNE;
            break;
        }

        ivCopyIn = malloc(16);
        memcpy(ivCopyIn, dv->random + dataIV_offset, 16);
        ivCopyOut = malloc(16);
        memcpy(ivCopyOut, dv->random + dataIV_offset, 16);

        // write all blocks in order
        previousBlock = 0;
        int listIdx = 0;
        int dataCursor = 0;
        for (; listIdx < occupiedBlocks.size; listIdx++)
        {
            currentBlock = (unsigned int)occupiedBlocks.list[listIdx];

            // determine increment and skip blocks
            int increment = currentBlock - previousBlock;
            if (dataCursor < entryData.size)
            {
                if (currentBlock <= noBlocks && increment) // & dataCursor < entryData.size
                {
                    // content to copy (skipped)
                    char *copy = file_readBlocks(&dataIn, increment);
                    file_writeBlocks(&dataOut, copy, increment);
                    free(copy);
                }
                aes_incrementCounter(ivCopyIn, increment);
                aes_incrementCounter(ivCopyOut, increment);

                // write entry data
                int n = MIN(14, entryData.size - dataCursor);
                dec = malloc(16);
                memcpy(dec, entryData.str + dataCursor, n); // copy data
                memset(dec + n, 0x22, 14 - n); // default value
                dataCursor += n;
                if (dataCursor < entryData.size)
                {
                    // write continuation block
                    smallEndianStr((unsigned int)occupiedBlocks.list[listIdx + 1], dec + 14, 2);
                }
                else
                {
                    // no continuation block
                    memset(dec + 14, 0, 2);
                }

                AES_ENC_BLK(dv, dec, ivCopyOut, (unsigned char **)&enc);
                file_writeBlocks(&dataOut, enc, 1);
                
                if (DV_DEBUG)
                {
                    printHexString(dec, 16, "modBlk");
                    printHexString(enc, 16, "encMod");
                }

                free(enc);
                free(dec);
            }
            else
            {
                // skip input block
                file_advanceCursorBlocks(&dataIn, 1);
                aes_incrementCounter(ivCopyIn, 1);
                for (int i = 1; i < increment; i++)
                {
                    aes_incrementCounter(ivCopyIn, 1);
                    aes_incrementCounter(ivCopyOut, 1);

                    // decrypt and re-encrypt with new IV
                    enc = file_readBlocks(&dataIn, 1);
                    AES_DEC_BLK(dv, enc, ivCopyIn, &dec);
                    AES_ENC_BLK(dv, dec, ivCopyOut, (unsigned char **)&enc);
                    file_writeBlocks(&dataOut, enc, 1);

                    free(enc);
                    free(dec);

                    // decrease startIdxs on subsequent entries
                    dv_advanceStartIdx(dv->idIdxMap.root, currentBlock);
                }
            }

            previousBlock = currentBlock;
        }

        file_close(&dataIn);
        file_close(&dataOut);

        file_copy(data_fp, data_tmp_fp);
    } while (false);

    conditionalFree(ivCopy, free);
    conditionalFree(ivCopyIn, free);
    conditionalFree(ivCopyOut, free);
    conditionalFree(dec, free);
    conditionalFree(enc, free);
    strstream_clear(&entryData);
    dynarr_free(&occupiedBlocks);

    return retCode;
}

int dv_setEntryData(dv_app *dv, const char *name, const char *category, const char *data)
{
    dv_deleteEntryData(dv, name, category);
    return dv_createEntryData(dv, name, category, data);
}

int dv_accessEntryData(dv_app *dv, const char *name, const char *category, char **buffer)
{
    if (!dv->loggedIn)
    {
        return DV_LOGGED_OUT;
    }

    // find entry id
    unsigned int entryId = (unsigned int)avl_get(dv->nameIdMap, (void *)name);
    if (!entryId)
    {
        return DV_INVALID_INPUT;
    }

    unsigned char catId = (unsigned char)(unsigned int)avl_get(dv->catIdMap, (void *)category);
    if (!catId)
    {
        return DV_INVALID_INPUT;
    }

    if (DV_DEBUG)
    {
        printf("Entry id for %s: %d\n", name, entryId);
        printf("Category id for %s: %d\n", category, catId);
    }

    strstream ret = strstream_allocDefault();
    unsigned int previousBlock = 0;
    unsigned int currentBlock = (unsigned int)btree_search(dv->idIdxMap, entryId);
    unsigned int nextBlock = 0;

    int retCode = DV_SUCCESS;

    do
    {
        file_struct dataFile;
        if (!file_openBlocks(&dataFile, data_fp, "rb", 16))
        {
            retCode = DV_FILE_DNE;
            break;
        }
        unsigned int noBlocks = dataFile.len >> 4; // len / 16

        // skip first block
        file_advanceCursorBlocks(&dataFile, 1);

        // copy IV
        unsigned char *ivCopy = malloc(16);
        memcpy(ivCopy, dv->random + dataIV_offset, 16);

        bool completed = false;
        bool onTarget = false;
        bool scanData = false;
        unsigned int startIdx;

        while (currentBlock < noBlocks)
        {
            // skip blocks
            int increment = currentBlock - previousBlock;
            file_advanceCursorBlocks(&dataFile, increment - 1);
            aes_incrementCounter(ivCopy, increment);

            // read block
            char *enc = file_readBlocks(&dataFile, 1);
            unsigned char *dec = NULL;
            AES_DEC_BLK(dv, enc, ivCopy, &dec);

            if (DV_DEBUG)
            {
                printf("==Block %d: increment by %d\n", currentBlock, increment);
                printHexString(enc, 16, "encBlock");
                printHexString(ivCopy, 16, "ivInc");
                printHexString(dec, 16, "decBlock");
            }

            if (onTarget)
            {
                // read from beginning of block
                startIdx = 0;
            }

            int i = 0;
            for (; i < 16 - sizeof(unsigned short); i++)
            {
                if (!scanData)
                {
                    scanData = true;

                    if (dec[i] == catId)
                    {
                        // found target
                        onTarget = true;
                        startIdx = i + 1;
                    }
                }

                if (!dec[i])
                {
                    // terminator character
                    scanData = false;

                    if (onTarget)
                    {
                        // finished reading target
                        completed = true;
                        break;
                    }
                }
            }

            if (onTarget)
            {
                // write characters to the buffer
                strstream_read(&ret, dec + startIdx, i - startIdx);
            }

            // read continuation block
            nextBlock = smallEndianValue(dec + 14, 2);

            free(enc);
            free(dec);

            if (completed || !nextBlock)
            {
                // either completed entry or read all data
                break;
            }

            // update counters
            previousBlock = currentBlock;
            currentBlock = nextBlock;
        }

        file_close(&dataFile);
        free(ivCopy);

        if (!completed)
        {
            // data does not exist
            retCode = DV_INVALID_INPUT;
            break;
        }

        // set return value
        *buffer = malloc(ret.size + 1);
        memcpy(*buffer, ret.str, ret.size + 1);
    } while (false);

    strstream_clear(&ret);
    return retCode;
}

void dv_advanceStartIdx(btree_node *root, unsigned int skipBlock)
{
    // do an inorder traversal
    if (root)
    {
        int i = 0;
        for (; i < root->n; i++)
        {
            // traverse to children
            if (root->noChildren)
            {
                dv_advanceStartIdx(root->children[i], skipBlock);
            }

            unsigned int idx = (unsigned int)root->vals[i];
            if (idx > skipBlock)
            {
                root->vals[i] = (void*)(idx - 1);
            }
        }
        // traverse to last child
        if (root->noChildren)
        {
             dv_advanceStartIdx(root->children[i], skipBlock);
        }
    }
}