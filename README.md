# data-vault
 Secure data storage application written in C.
 Follows [this playlist](https://www.youtube.com/playlist?list=PLysLvOneEETNeg2YqISscjqA4udYRuGDb) on YouTube

# Data Values
Variable Name | Purpose | Source
------------- | ------- | ------

# Data Files

File Name | Purpose | Organization | Encryption
--------- | ------- | ------------ | ----------
iv.dv | Store IV's and salts | <ul><li>Blocks of 16 bytes</li></ul><ol><li>userPwdSalt</li><li>dataKeyIV</li><li>dataIV</li><li>mapIV</li><li>btreeIV</li><li>categoryIV</li></ol> | none
**data.dv** | Store encrypted data | <ul><li>blocks of 16 bytes for AES</li><ul><li>data in first 12 bytes</li><ul><li>entry: `short categoryId`, `string name`, `'\0'`</li></ul><li>`int continuationBlock` in last 4 bytes</ul></ul> | `AES_256(k = dataKey, iv = dataIV)`
map.dv | Map entry names to entry id | <ul><li>List of entries</li><li>entry: `string name`, `'\0'`, `int entryId`</li></ul> | `AES_256(k = dataKey, iv = mapIV)`
btree.dv | Map entry ids to initial block in data.dv | <ul><li>List of entries</li><li>entry: `int numericalId`, `int initialBlock`</li></ul> | `AES_256(k = dataKey, iv = btreeIV)`
categories.dv | Map category ids to category name | <ul><li>List of entries</li><li>entry: `short numericalId`, `string name`, `'\0'`</li></ul> | `AES_256(k = dataKey, iv = categoryIV)`
pwd.dv | Store the hash of the user's password | <ul><li>64 bytes are hashed `userPwd`</li></ul> | `SHA3_512(salt = userPwdSalt)`
datakey.dv | Store the data key | <ul><li>32 bytes are `dataKey`</li></ul> | `AES_256(k = kek, iv = dataKeyIV)`

*All numerical id's are represented as unsigned values*

# Sequences

## Login
### Goal: generate keys; load, decrypt, and parse maps
```
```

## Logout
### Goal: save; free memory
```
```

## Save
### Goal: stringify, encrypt, and save maps
```
```

## Create entry
```
```

## Delete entry
```
```

## Access entry
```
```

## Create/Modify entry data
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