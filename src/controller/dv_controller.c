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
    sha3_context *hashCtx = NULL;
    unsigned char *hash = NULL;
    unsigned char *dataKey = NULL;
    unsigned char *kek = NULL;
    unsigned char *encDataKey = NULL;

    do
    {
        // generate salts and IVs
        if (!(random = newRandomBytes(0x7)))
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
        sha3_initContext(hashCtx, SHA3_512);
        sha3_update(hashCtx, userPwd, n);
        sha3_update(hashCtx, random + userPwdSalt_offset, 16); // update with salt
        sha3_digest(hashCtx, &hash);
        
        // write to file
        if (!file_writeContents(pwd_fp, hash, hashCtx->ret_len))
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

    sha3_context *hashCtx = NULL;
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
        sha3_initContext(hashCtx, SHA3_512);
        sha3_update(hashCtx, userPwd, n);
        sha3_update(hashCtx, dv->random + userPwdSalt_offset, 16); // concatenate salt
        sha3_digest(hashCtx, &hash);

        // read expected value
        file_struct pwdFile;
        if (file_open(&pwdFile, pwd_fp, "rb"))
        {
            // read file
            expected = file_read(&pwdFile, hashCtx->ret_len);

            // compare
            if (memcmp(hash, expected, hashCtx->ret_len))
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