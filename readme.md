# Installer la configuration pour utiliser qrypto :
```
$ sudo apt install gcc
$ sudo apt install g++
$ sudo apt install make
$ sudo apt install openssl
$ sudo apt install libssl-dev
```
**Si librairie manquante :**

Télécharger :
```
$ wget http://nz2.archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2.22_amd64.deb
$ sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2.22_amd64.deb
```

Ou reprendre du path lib :
```
$ cp /blkchn_code_/src/lib/libcrypto.so.1.1 /blkchn_code_/src/wallet/libcrypto.so.1.1
```

## SQLite3
```
$ sudo apt install sqlite3
$ sudo apt install libqlite3-dev
```

## SQCipher
```
$ sudo apt install sqlcipher
$ sudo apt install libsqlcipher-dev
```
**Si librairie manquante :**

Installer sqlcipher à partir du dossier :
```
$ cd blkchn_code_/src/sqlcipher-master
$ ./configure --enable-tempstore=yes CFLAGS="-DSQLITE_HAS_CODEC" LDFLAGS="-lcrypto"
$ make
$ sudo make install DESTDIR=/
```

Ou reprendre du path lib :
```
$ cp /blkchn_code_/src/lib/libsqlcipher.so.0 /blkchn_code_/src/wallet/libsqlcipher.so.0
```

## L'exécutable du wallet 
```
$ make
$ ./gen_key_mode3
```
OU
```
$ make gen_key_mode3
$ ./gen_key_mode3
```

## L'exécutable du consensus 
```
$ make
$ ./run_consensus
```
OU
```
$ make run_consensus
$ ./run_consensus
```

# Installations complètes de SQLCipher et LevelDB (inutile pour le lancement du projet qrypto) :

## SQLCipher (SEE require a License) :
```
$ wget https://github.com/sqlcipher/sqlcipher/archive/master.zip
$ unzip master.zip
$ cd sqlcipher-master
$ sudo apt-get update
$ sudo apt-get install libssl-dev
$ ./configure --enable-tempstore=yes CFLAGS="-DSQLITE_HAS_CODEC" LDFLAGS="-lcrypto"
$ make
$ sudo make install DESTDIR=/
```

## LevelDB :
```
$ git clone --recurse-submodules https://github.com/google/leveldb.git
$ mkdir -p leveldb/build && cd leveldb/build
$ cmake -DCMAKE_BUILD_TYPE=Release ..
$ cmake --build .
```
Avec wsl :
```
$ echo 'export PATH="/mnt/VOTRE_DISQUE(d ou c)/VOTRE_PATH/leveldb/build:$PATH"' >> ~/.bashrc
$ echo $PATH | grep -q "/mnt/VOTRE_DISQUE(d ou c)/VOTRE_PATH/leveldb/build" && echo "leveldbutil est dans PATH" || echo "leveldbutil n'est pas dans PATH"
$ source ~/.bashrc
```