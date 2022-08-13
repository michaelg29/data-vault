gcc -o C:/src/data-vault/test/run/main ^
	C:/src/data-vault/test/main.c ^
	C:/src/data-vault/src/datavault.c ^
	C:/src/data-vault/src/controller/dv_controller.c ^
	C:/src/data-vault/src/controller/dv_persistence.c ^
	C:/src/data-vault/src/lib/cmathematics/cmathematics.c ^
	C:/src/data-vault/src/lib/cmathematics/data/encryption/aes.c ^
	C:/src/data-vault/src/lib/cmathematics/data/hashing/hmac.c ^
	C:/src/data-vault/src/lib/cmathematics/data/hashing/pbkdf.c ^
	C:/src/data-vault/src/lib/cmathematics/data/hashing/sha.c ^
	C:/src/data-vault/src/lib/cmathematics/data/hashing/sha1.c ^
	C:/src/data-vault/src/lib/cmathematics/data/hashing/sha2.c ^
	C:/src/data-vault/src/lib/cmathematics/data/hashing/sha3.c ^
	C:/src/data-vault/src/lib/cmathematics/lib/arrays.c ^
	C:/src/data-vault/src/lib/cmathematics/util/numio.c ^
	C:/src/data-vault/src/lib/ds/avl.c ^
	C:/src/data-vault/src/lib/ds/btree.c ^
	C:/src/data-vault/src/lib/ds/dynamicarray.c ^
	C:/src/data-vault/src/lib/ds/strstream.c ^
	C:/src/data-vault/src/lib/util/fileio.c ^
	C:/src/data-vault/src/lib/util/mem.c ^
	C:/src/data-vault/src/view/terminal/terminal.c
cd C:/src/data-vault/test/run
C:/src/data-vault/test/run/main
cd C:\src\data-vault\test
pause