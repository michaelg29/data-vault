#include "dv_controller.h"

#include "../datavault.h"
#include "dv_persistence.h"

#include "../lib/cmathematics/util/numio.h"
#include "../lib/cmathematics/data/encryption/aes.h"
#include "../lib/cmathematics/data/hashing/sha.h"
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
    void *hashCtx = NULL;
    unsigned char *hash = NULL;
    unsigned char *dataKey = NULL;
    unsigned char *kek = NULL;
    unsigned char *encDataKey = NULL;

    do
    {
        // generate salts and IVs
        if (!(random = newRandomBytes(7 << 4)))
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
        hashCtx = sha_initContext(SHA3_512);
        sha_update(SHA3_512, hashCtx, userPwd, n);
        sha_update(SHA3_512, hashCtx, random + userPwdSalt_offset, 16); // update with salt
        sha_digest(SHA3_512, hashCtx, &hash);
        sha_free(hashCtx);

        // write to file
        if (!file_writeContents(pwd_fp, hash, sha_getRetLenIdx(SHA3_512)))
        {
            retCode = DV_FILE_DNE;
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
        }
    } while (false);

    conditionalFree(random, free);
    conditionalFree(hashCtx, sha_free);
    conditionalFree(hash, free);
    conditionalFree(dataKey, free);
    conditionalFree(kek, free);
    conditionalFree(encDataKey, free);

    return retCode;
}

int dv_login(dv_app *dv, unsigned char *userPwd, int n)
{
    int retCode = DV_SUCCESS;

    void *hashCtx = NULL;
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
        if (!(dv->random = file_readContents("iv.dv")))
        {
            retCode = DV_FILE_DNE;
            break;
        }

        /**
         * VALIDATE INPUT PASSWORD
         */
        // generate input hash
        hashCtx = sha_initContext(SHA3_512);
        sha_update(SHA3_512, hashCtx, userPwd, n);
        sha_update(SHA3_512, hashCtx, dv->random + userPwdSalt_offset, 16); // concatenate salt
        sha_digest(SHA3_512, hashCtx, &hash);
        sha_free(hashCtx);

        // read expected value
        file_struct pwdFile;
        if (file_open(&pwdFile, "pwd.dv", "rb"))
        {
            // read file
            expected = file_read(&pwdFile, sha_getRetLenIdx(SHA3_512));

            // compare
            if (memcmp(hash, expected, sha_getRetLenIdx(SHA3_512)))
            {
                dv_kill(dv);
                return DV_INVALID_INPUT;
            }
            // else succeeded

            file_close(&pwdFile);
        }
        else
        {
            return DV_FILE_DNE;
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
    } while (false);

    conditionalFree(hashCtx, sha_free);
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