# data-vault
 Secure data storage application written in C.
 Follows [this playlist](https://www.youtube.com/playlist?list=PLysLvOneEETNeg2YqISscjqA4udYRuGDb) on YouTube

# Data Values
Variable Name | Purpose | Source
------------- | ------- | ------

# Data Files

File Name | Purpose | Organization | Encryption
--------- | ------- | ------------ | ----------
iv.dv | Store IV's and salts | <ul><li>Blocks of 16 bytes</li></ul><ol><li>userPwdSalt</li><li>kekSalt</li><li>dataKeyIV</li><li>dataIV</li><li>mapIV</li><li>btreeIV</li><li>categoryIV</li></ol> | none
**data.dv** | Store encrypted data | <ul><li>blocks of 16 bytes for AES</li><ul><li>data in first 12 bytes</li><ul><li>entry: `short categoryId`, `string name`, `'\0'`</li></ul><li>`int continuationBlock` in last 4 bytes</ul></ul> | `AES_256(k = dataKey, iv = dataIV)`
map.dv | Map entry names to entry id | <ul><li>List of entries</li><li>entry: `string name`, `'\0'`, `int entryId`</li></ul> | `AES_256(k = dataKey, iv = mapIV)`
btree.dv | Map entry ids to initial block in data.dv | <ul><li>List of entries</li><li>entry: `int numericalId`, `int initialBlock`</li></ul> | `AES_256(k = dataKey, iv = btreeIV)`
categories.dv | Map category ids to category name | <ul><li>List of entries</li><li>entry: `short numericalId`, `string name`, `'\0'`</li></ul> | `AES_256(k = dataKey, iv = categoryIV)`
pwd.dv | Store the hash of the user's password | <ul><li>64 bytes are hashed `userPwd`</li></ul> | `SHA3_512(salt = userPwdSalt)`
datakey.dv | Store the data key | <ul><li>32 bytes are `dataKey`</li></ul> | `AES_256(k = kek, iv = dataKeyIV)`

*All numerical id's are represented as unsigned values*

# Sequences

## Create Account
#### Goal: hash password, generate salts/ivs and data key, create data files
```
Input: userPwd
```

1) Create all files
    iv.dv
    data.dv
    map.dv
    btree.dv
    categories.dv
    pwd.dv
    datakey.dv
2) Generate salts and IV's, output into iv.dv
```
    userPwdSalt = randomBytes(16)
    kekSalt = randomBytes(16)
    dataKeyIV = randomBytes(16)
    dataIV = randomBytes(16)
    mapIV = randomBytes(16)
    btreeIV = randomBytes(16)
    categoryIV = randomBytes(16)
    write("iv.dv", userPwdSalt, kekSalt, dataKeyIV, dataIV, mapIV, btreeIV, categoryIV)
```
3) Process userPwd and generate dataKey
```
    write("pwd.dv", SHA3_512(salt = userPwdSalt, txt = userPwd))
    dataKey = randomBytes(16)
    keyEncryptionKey = PBKDF2(k = userPwd, salt = kekSalt, dklen = 32)
    write("datakey.dv", AESenc_256(k = keyEncryptionKey, txt = dataKey, iv = dataKeyIV))
```

## Login
#### Goal: generate keys; load, decrypt, and parse maps
```
Input: userPwd
```

1) Read salts and iv's from iv.dv
```
    // sequential list
    randList = content("iv.dv")
    userPwdSalt = randList[0:16)
    kekSalt = randList[16:32)
    dataKeyIV = randList[32:48)
    dataIV = randList[48:64)
    mapIV = randList[64:80)
    btreeIV = randList[80:96)
    categoryIV = randList[96:112)
```
2) Validate userPwd
```
    // compare hashes
    inputHash = SHA3_512(salt = userPwdSalt, txt = userPwd)
    assertEquals(inputHash, contents("pwd.dv"))
```
3) Decrypt dataKey
```
    // derive key encryption key from userPwd
    keyEncryptionKey = PBKDF2(k = userPwd, salt = kekSalt, dklen = 32)
    free(userPwd)
    // decrypt dataKey
    dataKey = AESdec_256(k = keyEncryptionKey, txt = contents("dataKey.dv"), iv = dataKeyIV)
    free(keyEncryptionKey)
```
4) Generate AES key schedule
```
    // save in memory for use throughout program when decrypting data
    keySchedule = AESgenKeySchedule_256(k = dataKey)
```
5) Allocate memory to maps
```
    nameIdMap = avl_tree()
    idIdxMap = btree()
    categoryIdMap = avl_tree()
```
6) Call the Load sequence

## Logout
#### Goal: save; free memory
1) Call the Save sequence
2) free memory
```
    free(dataKey)
    free(keySchedule)
    btree_free(entryMap)
    avl_free(nameMap)
    avl_free(categoryMap)
    maxId = 0
```

## Load
#### Goal: decrypt and parse maps
1) Decrypt and load btree.dv
```
    btreeStr = AESdec_256(k = dataKey, txt = contents("btree.dv"), iv = btreeIV)
    for each entry
        // parse 2 4-byte numerical values for id and initialBlock
        read 4 chars
            id = val({chars}, base = 256)
            maxId = MAX(id, maxId)
        read 4 chars
            initialBlock = val({chars}, base = 256)
        // insert key value pair
        insert (id, initialBlock) into idIdxMap
```
2) Decrypt and load map.dv
```
    mapStr = AESdec_256(k = dataKey, txt = contents("map.dv"), iv = mapIV)
    for each entry
        read chars until \0
            name = {chars}
        // parse 4 byte unsigned numerical value for id
        read 4 chars
            id = val({chars}, base = 256)
        // insert key value pair
        insert (name, id) into nameIdMap
```
3) Decrypt and load categories.dv
```
    categoriesStr = AESdec_256(k = dataKey, txt = contents("categories.dv"), iv = categoryIV)
    for each entry
        // parse 1 byte unsigned numerical value for id
        read 1 char
            id = val(char, base = 256)
        read chars until \0
            name = {chars}
        // insert key value pair
        insert (name, id) into categoryIdMap
```

## Save
#### Goal: stringify, encrypt, and save maps
1) Stringify and encrypt nameMap
```
    for each entry
        // stringify id and concatenate to name
        entryStr = entry.name, \0, smallEndian(entry.id)
        concatenate entryStr to nameMapStr
    write AESenc_256(k = dataKey, txt = entryStr, iv = mapIV) into map.dv
```
2) Stringify and encrypt entryMap
```
    for each entry
        // stringify id and initial block and concatenate
        entryStr = smallEndian(entry.id), smallEndian(entry.initialBlock)
        concatenate entryStr to btreeStr
    write AESenc_256(k = dataKey, txt = btreeStr, iv = btreeIV) into btree.dv
```
3) Stringify and encrypt cateogriesMap
```
    for each entry
        // stringify id and concatenate to name
        entryStr = smallEndian(entry.id), entry.name, \0
        concatenate entryStr to categoriesStr
    write AESenc_256(k = dataKey, txt = categoriesStr, iv = categoriesIV) into categories.dv
```
4) Write salts
```
    write userPwdSalt + kekSalt + dataKeyIV + dataIV + mapIV + btreeIV + categoryIV into iv.dv
```

## Create entry
```
Input: name
```

1) Insert into name map
```
    insert (name, ++maxId) into nameIdMap
```
2) Create initial block
```
    initBlock = filelen(data.dv) / 16 + 1
    block = 0, randomBytes(11), smallEndian(0)
    increment dataIV by initBlock
    append AESenc_256(k = dataKey, txt = block, iv = dataIV) to data.dv
```
3) Insert into index map
```
    insert (maxId, initBlock) into idIdxMap
```

## Delete entry
```
```

## Access entry
```
```

## Create entry data
```
Input: name, category, new data
```

1) Find the category id
```
    catId = categoryIdMap(category)
    if catId = 0
        catId = ++maxCatId
        insert (category, catId) into categoryIdMap
```
2) Find the entry id
```
    id = nameIdMap(name)
    if id = 0
        // did not find name
        id = call Create Entry sequence
```
3) Write data
```
    previousBlock = 0
    currentBlock = idIdxMap(id)
    while true
        increment dataIV by currentBlock - previousBlock
        blk = AESdec_256(k = dataKey, txt = block(data.dv, currentBlock), iv = dataIV)
        modified = false

        for i in [0:12)
            cat = blk[i]
            if cat = 0
                blk[i] = catId

                if i != 11
                    write new data into blk[i+1:12)
                    modified = true
                if more data
                    nextBlock = filelen(data.dv) / 16 + 1
                    blk[12:16) = smallEndian(nextBlock)

        if modified
            write AES_enc(k = dataKey, txt = blk, iv = dataIV) into data.dv at currentBlock

        if nextBlock != 0
            previousBlock = currentBlock
            currentBlock = nextBlock
        else
            break
```

## Modify entry data
```
```

## Delete entry data
```
```

## Change user password
```
```

## Change data encryption key
```
```