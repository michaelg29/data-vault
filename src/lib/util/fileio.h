#include <stdio.h>

#include "../ds/strstream.h"
#include "../cmathematics/cmathematics.h"

#ifndef FILEIO_H
#define FILEIO_H

typedef struct
{
    FILE *fp;

    int cursor;
    int len;
    int blockSize;
} file_struct;

bool file_create(const char *path);
char *file_readContents(const char *path);
bool file_writeContents(const char *path, void *buffer, int n);
bool file_writeContentBlocks(const char *path, void *buffer, int n, int blkSize);
bool file_copy(const char *dstPath, const char *srcPath);

bool file_open(file_struct *f, const char *path, const char *mode);
bool file_openBlocks(file_struct *f, const char *path, const char *mode, unsigned int blockSize);
int file_length(file_struct *f);
void file_setBlockSize(file_struct *f, int size);

void file_advanceCursor(file_struct *f, int n);
void file_advanceCursorBlocks(file_struct *f, int n);

void file_retreatCursor(file_struct *f, int n);
void file_retreatCursorBlocks(file_struct *f, int n);

char *file_read(file_struct *f, int n);
char *file_readBlocks(file_struct *f, int n);

void file_write(file_struct *f, void *buffer, int n);
void file_writeBlocks(file_struct *f, void *buffer, int noBlocks);

void file_close(file_struct *f);

bool directoryExists(const char *absolutePath);

#endif // FILEIO_H