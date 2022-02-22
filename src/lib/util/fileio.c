#include "fileio.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

bool file_create(const char *path)
{
    file_struct newFile;

    bool ret = file_open(&newFile, path, "w");

    if (!ret)
    {
        return false;
    }

    file_close(&newFile);

    return true;
}

char *file_readContents(const char *path)
{
    char *ret = NULL;

    file_struct f;
    if (file_open(&f, path, "rb") && f.len)
    {
        ret = file_read(&f, f.len);
        file_close(&f);
    }

    return ret;
}

bool file_writeContents(const char *path, void *buffer, int n)
{
    if (!(buffer && n))
    {
        return true;
    }

    file_struct f;
    if (file_open(&f, path, "wb"))
    {
        file_write(&f, buffer, n);
        file_close(&f);
        return true;
    }
    else
    {
        return false;
    }
}

bool file_writeContentBlocks(const char *path, void *buffer, int n, int blkSize)
{
    if (!(buffer && n))
    {
        return true;
    }

    file_struct f;
    if (file_open(&f, path, "wb"))
    {
        file_setBlockSize(&f, blkSize);
        file_writeBlocks(&f, buffer, n);
        file_close(&f);
        return true;
    }
    else
    {
        return false;
    }
}

bool file_open(file_struct *f, const char *path, const char *mode)
{
    f->fp = fopen(path, mode);
    if (!f->fp)
    {
        return false;
    }

    f->cursor = 0;
    f->len = file_length(f);
    f->blockSize = 0;

    return true;
}

int file_length(file_struct *f)
{
    // move cursor to the end
    fseek(f->fp, 0L, SEEK_END);
    // get remaining length
    int ret = ftell(f->fp) - f->cursor;
    // return to original position
    fseek(f->fp, f->cursor, SEEK_SET);

    return ret;
}

void file_setBlockSize(file_struct *f, int size)
{
    f->blockSize = size;
}

void file_advanceCursor(file_struct *f, int n)
{
    n = MIN(n, f->len - f->cursor);

    if (n <= 0 || !f->fp)
    {
        return;
    }

    fseek(f->fp, f->cursor + n, SEEK_SET);

    f->cursor += n;
}

void file_advanceCursorBlocks(file_struct *f, int n)
{
    file_advanceCursor(f, f->blockSize ? n * f->blockSize : n);
}

void file_retreatCursor(file_struct *f, int n)
{
    n = MIN(n, f->cursor);

    if (n <= 0 || !f->fp)
    {
        return;
    }

    fseek(f->fp, f->cursor - n, SEEK_SET);

    f->cursor -= n;
}

void file_retreatCursorBlocks(file_struct *f, int n)
{
    file_retreatCursor(f, f->blockSize ? n * f->blockSize : n);
}

char *file_read(file_struct *f, int n)
{
    n = MIN(n, f->len - f->cursor);

    if (n <= 0 || !f->fp)
    {
        return NULL;
    }

    char *ret = malloc(n + 1);
    fread(ret, 1, n, f->fp);
    f->cursor += n;

    ret[n] = '\0';

    return ret;
}

char *file_readBlocks(file_struct *f, int n)
{
    return file_read(f, f->blockSize ? n * f->blockSize : n);
}

void file_write(file_struct *f, void *buffer, int n)
{
    if (n <= 0 || !f->fp)
    {
        return;
    }

    fwrite(buffer, 1, n, f->fp);
}

void file_writeBlocks(file_struct *f, void *buffer, int noBlocks)
{
    if (noBlocks <= 0 || !f->fp)
    {
        return;
    }

    fwrite(buffer, f->blockSize ? f->blockSize : 1, noBlocks, f->fp);
}

void file_close(file_struct *f)
{
    if (f->fp)
    {
        fclose(f->fp);
        f->fp = NULL;
    }
}