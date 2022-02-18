#include "dv_persistence.h"
#include "dv_controller.h"

#include "../lib/util/fileio.h"
#include "../lib/util/mem.h"

#include "../lib/cmathematics/util/numio.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

const char *iv_fp = "iv.dv";
const char *data_fp = "data.dv";
const char *data_tmp_fp = "data_tmp.dv";
const char *nameIdMap_fp = "nameIdMap.dv";
const char *idIdxMap_fp = "idIdxMap.dv";
const char *categoryIdMap_fp = "catIdMap.dv";
const char *pwd_fp = "pwd.dv";
const char *dk_fp = "dk.dv";

int dv_initFiles(unsigned char *random)
{
    bool ret = true;

    // create files
    ret = file_create(nameIdMap_fp);
    ret = file_create(idIdxMap_fp);
    ret = file_create(categoryIdMap_fp);

    // write into iv file
    ret = file_writeContents(iv_fp, random, 0x70);

    // write dataIV into data.dv
    ret = file_writeContents(data_fp, random, 16);

    return ret ? DV_SUCCESS : DV_FILE_DNE;
}

void readNameIdMap(dv_app *dv, strstream stream)
{
    int startOfEntryIdx = 0;
    char *name = NULL;
    char *idStr = NULL;

    for (int i = 0; i < stream.size; i++)
    {
        if (!stream.str[i])
        {
            // encountered end of string
            name = strstream_substrRange(&stream, startOfEntryIdx, i);
            idStr = strstream_substrLength(&stream, i + 1, 4);

            // insert into map
            dv->nameIdMap = avl_insert(
                dv->nameIdMap,
                name, (void *)smallEndianValue(idStr, 4));

            // update cursors
            startOfEntryIdx = i + 5;
            i += 4;

            free(idStr);
        }
    }
}

void readIdIdxMap(dv_app *dv, strstream stream)
{
    char *numStr = NULL;
    int id;
    int idx;

    for (int i = 0; i < stream.size; i += 2 * sizeof(int))
    {
        // read and parse id
        numStr = strstream_substrLength(&stream, i, 4);
        id = smallEndianValue(numStr, 4);
        free(numStr);

        // read and parse idx
        numStr = strstream_substrLength(&stream, i, 4);
        idx = smallEndianValue(numStr, 4);
        free(numStr);

        // insert into btree
        btree_insert(&dv->idIdxMap, id, (void *)idx);

        // update counter
        dv->maxEntryId = MAX(dv->maxEntryId, id);
    }
}

void readCatIdMap(dv_app *dv, strstream stream)
{
    int startOfEntryIdx = 0;
    char *name = NULL;
    char *idStr = NULL;

    for (int i = 0; i < stream.size; i++)
    {
        if (!stream.str[i])
        {
            // encountered end of string
            name = strstream_substrRange(&stream, startOfEntryIdx, i);
            idStr = strstream_substrLength(&stream, i + 1, 1);

            // insert into map
            dv->catIdMap = avl_insert(
                dv->catIdMap,
                name,
                (void *)smallEndianValue(idStr, 1));

            // update cursors
            startOfEntryIdx = i + 2;
            i += 1;

            free(idStr);
        }
    }
}

int dv_parse(dv_app *dv, const char *path, unsigned int offset,
             void (*readFunc)(dv_app *dv, strstream stream))
{
    char *enc = NULL;
    unsigned char *dec = NULL;
    strstream stream;

    file_struct file;
    if (file_open(&file, path, "rb"))
    {
        if (file.len)
        {
            // read
            enc = file_read(&file, file.len);
            // decrypt
            aes_decrypt_withSchedule(
                enc, file.len,
                dv->aes_key_schedule, AES_256_NR, AES_CTR,
                dv->random + offset,
                &dec);

            // pass to string stream
            stream = strstream_alloc(file.len);
            strstream_read(&stream, dec, file.len);

            // free variables
            free(enc);
            free(dec);
            file_close(&file);

            // TODO: parse
            readFunc(dv, stream);

            strstream_clear(&stream);
        }
        else
        {
            file_close(&file);
        }
    }
    else
    {
        return DV_FILE_DNE;
    }

    return DV_SUCCESS;
}

int dv_load(dv_app *dv)
{
    int retCode = DV_SUCCESS;

    // main body
    do
    {
        // decrypt and load nameIdMap
        dv->nameIdMap = avl_createEmptyRoot(strkeycmp);
        if (retCode = dv_parse(
                dv, nameIdMap_fp, nameIdIV_offset, readNameIdMap))
        {
            break;
        }

        // decrypt and load idIdxMap
        dv->idIdxMap = btree_new(5);
        if (retCode = dv_parse(
                dv, idIdxMap_fp, idIdxIV_offset, readIdIdxMap))
        {
            break;
        }

        // decrypt and load catIdMap
        dv->catIdMap = avl_createEmptyRoot(strkeycmp);
        if (retCode = dv_parse(
                dv, categoryIdMap_fp, catIdIV_offset, readCatIdMap))
        {
            break;
        }
    } while (false);

    return retCode;
}

void writeStrId(strstream *out, avl *root, int idSize)
{
    // do a postorder traversal

    if (root && root->key)
    {
        // visit root
        unsigned char *name = root->key;
        unsigned int id = (unsigned int)root->val;
        unsigned char *idStr = smallEndianStr(id);

        // format: entry.name, \0, str(entry.id)
        strstream_read(out, name, strlen(name) + 1);
        strstream_read(out, idStr, idSize);

        free(idStr);

        // visit children
        if (root->left)
        {
            writeStrId(out, root->left, idSize);
        }
        if (root->right)
        {
            writeStrId(out, root->right, idSize);
        }
    }
}

void writeIdIdx(strstream *out, btree_node *root)
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
                writeIdIdx(out, root->children[i]);
            }

            // write current key-value pair
            unsigned char *numStr = NULL;
            numStr = smallEndianStr(root->keys[i]);
            strstream_read(out, numStr, 4);
            numStr = smallEndianStr((unsigned int)root->vals[i]);
            strstream_read(out, numStr, 4);

            free(numStr);
        }
        // traverse to last child
        if (root->noChildren)
        {
            writeIdIdx(out, root->children[i]);
        }
    }
}

void writeNameIdMap(void *nameIdMap, strstream *stream)
{
    writeStrId(stream, (avl *)nameIdMap, sizeof(int));
}

void writeIdIdxMap(void *idIdxMap, strstream *stream)
{
    writeIdIdx(stream, ((btree *)idIdxMap)->root);
}

void writeCatIdMap(void *catIdMap, strstream *stream)
{
    writeStrId(stream, (avl *)catIdMap, sizeof(char));
}

int dv_stringify(dv_app *dv, const char *path, unsigned int offset,
                 void *structure, void (*dumpFunc)(void *structure, strstream *stream))
{
    strstream stream;
    file_struct file;

    if (file_open(&file, path, "wb"))
    {
        // stringify
        strstream out = strstream_allocDefault();
        dumpFunc(structure, &out);

        if (DV_DEBUG)
        {
            printf("%s\n", path);
            printHexString(out.str, out.size, "out");
        }

        // encrypt
        unsigned char *encOut = NULL;
        aes_encrypt_withSchedule(
            out.str, out.size,
            dv->aes_key_schedule, AES_256_NR, AES_CTR,
            dv->random + offset,
            &encOut);

        // write to file
        file_write(&file, encOut, out.size);
        file_close(&file);

        // free variables
        strstream_clear(&out);
        free(encOut);
    }
    else
    {
        return DV_FILE_DNE;
    }

    return DV_SUCCESS;
}

int dv_save(dv_app *dv)
{
    int retCode = DV_SUCCESS;

    do
    {
        if (retCode = dv_stringify(dv, nameIdMap_fp, nameIdIV_offset,
                                   dv->nameIdMap, writeNameIdMap))
        {
            break;
        }

        if (retCode = dv_stringify(dv, idIdxMap_fp, idIdxIV_offset,
                                   &dv->idIdxMap, writeIdIdxMap))
        {
            break;
        }

        if (retCode = dv_stringify(dv, categoryIdMap_fp, catIdIV_offset,
                                   dv->catIdMap, writeCatIdMap))
        {
            break;
        }
    } while (false);

    return retCode;
}