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

    // generate salts and IVs
    unsigned char *random = newRandomBytes(7 << 4); // 7 * 16
    dv_initFiles(random);

    /**
     * HASH userPwd
     */
    // generate hash
    sha3_context *hashCtx = sha_initContext(SHA3_512);
    sha_update(SHA3_512, hashCtx, userPwd, n);
    sha_update(SHA3_512, hashCtx, random + userPwdSalt_offset, 16); // update with salt
    unsigned char *hash;
    sha_digest(SHA3_512, hashCtx, &hash);
    sha_free(hashCtx);

    // write to file
    if (!file_writeContents(pwd_fp, hash, sha_getRetLenIdx(SHA3_512)))
    {
        free(hash);
        return DV_FILE_DNE;
    }

    /**
     * DATA KEY
     */
    // generate
    unsigned char *dataKey = newRandomBytes(DV_KEYLEN);
    unsigned char *kek;
    pbkdf2_hmac_sha(userPwd, n,
                    random + kekSalt_offset, 16,
                    10, SHA512_STR, DV_KEYLEN, &kek);

    // encrypt key
    unsigned char *encDataKey;
    aes_encrypt(dataKey, 16,
                kek, AES_256, AES_CTR,
                random + dataKeyIV_offset,
                &encDataKey);

    // write encrypted data key
    if (!file_writeContents(dk_fp, encDataKey, DV_KEYLEN))
    {
        return DV_FILE_DNE;
    }

    // free variables
    free(dataKey);
    free(kek);
    free(encDataKey);
    free(random);

    return DV_SUCCESS;
}

int dv_login(dv_app *dv, unsigned char *userPwd, int n)
{
    // initialize memory
    dv_init(dv);

    // read salts/ivs
    dv->random = file_readContents("iv.dv");

    /**
     * VALIDATE INPUT PASSWORD
     */
    // generate input hash
    sha3_context *hashCtx = sha_initContext(SHA3_512);
    sha_update(SHA3_512, hashCtx, userPwd, n);
    sha_update(SHA3_512, hashCtx, dv->random + userPwdSalt_offset, 16); // concatenate salt
    unsigned char *hash;
    sha_digest(SHA3_512, hashCtx, &hash);
    sha_free(hashCtx);

    // read expected value
    file_struct pwdFile;
    if (file_open(&pwdFile, "pwd.dv", "rb"))
    {
        // read file
        char *expected = file_read(&pwdFile, sha_getRetLenIdx(SHA3_512));

        // compare
        if (memcmp(hash, expected, sha_getRetLenIdx(SHA3_512)))
        {
            dv_kill(dv);
            return DV_INVALID_INPUT;
        }
        // else succeeded

        file_close(&pwdFile);

        free(hash);
        free(expected);
    }
    else
    {
        return DV_FILE_DNE;
    }

    /**
     * DATA KEY
     */
    // derive key encryption key
    unsigned char *kek;
    pbkdf2_hmac_sha(userPwd, n,
                    dv->random + kekSalt_offset, 16,
                    10, SHA512_STR, DV_KEYLEN, &kek);

    // decrypt data key
    file_struct dkFile;
    if (file_open(&dkFile, "dk.dv", "rb"))
    {
        // read
        char *encDataKey = file_read(&dkFile, DV_KEYLEN);
        file_close(&dkFile);

        // decrypt
        unsigned char *tmp;
        aes_decrypt(encDataKey, DV_KEYLEN,
                    kek, AES_256, AES_CTR,
                    dv->random + dataKeyIV_offset, &tmp);
        memcpy(dv->dataKey, tmp, DV_KEYLEN);

        // free values
        free(tmp);
        free(encDataKey);
        free(kek);
    }
    else
    {
        free(kek);
        return DV_FILE_DNE;
    }

    // generate AES key schedule
    aes_generateKeySchedule(dv->dataKey, AES_256, dv->aes_key_schedule);

    // call the load sequence
    int res = dv_load(dv);

    if (!res)
    {
        // update state
        dv->loggedIn = true;

        return DV_SUCCESS;
    }
    else
    {
        dv_kill(dv);
        return res;
    }
}

int dv_logout(dv_app *dv)
{
    int res = dv_save(dv);

    if (res)
    {
        return res;
    }

    dv_kill(dv);

    return DV_SUCCESS;
}