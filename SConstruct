import os
import copy
SetOption("random", 1)

def get_static_library_name(node):
    return os.path.basename(str(node)[:-2])[3:-2]

def get_shared_library_name(node):
    return os.path.basename(str(node)[:-2])[3:-3]

# depend library

env = Environment(CCFLAGS='-fpermissive -g -O2 -std=c++11', LINKFLAGS='-pthread', CPPPATH=[
    "#src", "#depend/fly/src",
    "#depend/snappy",
    "#depend/snappy/build",
    "#depend/leveldb/include",
    "#depend/fly/depend/rapidjson/include",
    "#depend/fly/depend",
    "#depend/secp256k1/include",
    "#depend/openssl/include"
])

fly = File('#depend/fly/build/bin/libfly.a')
crypto = File('#depend/openssl/libcrypto.a')
cryptopp = File('#depend/fly/depend/cryptopp/libcryptopp.a')
secp256k1 = File('#depend/secp256k1/.libs/libsecp256k1.a')
snappy = File('#depend/snappy/build/libsnappy.a')
leveldb = File('#depend/leveldb/out-static/libleveldb.a')
env.Command([fly, cryptopp], None, "cd depend/fly && scons -c && scons")
env.Command(secp256k1, None, "cd depend/secp256k1 && ./autogen.sh && ./configure --enable-module-recovery && make clean && make")
env.Command(snappy, None, "cd depend/snappy && mkdir -p build && cd build && cmake3 .. && make clean && make")
env.Command(crypto, None, "cd depend/openssl && ./config no-shared && make clean && make")
env.Command(leveldb, None, "cd depend/leveldb && make clean && CXXFLAGS='-I../snappy -I../snappy/build' LDFLAGS=-L../snappy/build make")
Depends(leveldb, snappy)

libs = [
    fly,
    cryptopp,
    secp256k1,
    leveldb,
    snappy,
    crypto,
    "dl"
]

lib_path = [
]

env.Replace(LIBS=libs, LIBPATH=lib_path)
Export("env")
Export("crypto")
askcoin = SConscript("src/SConscript", variant_dir="build/askcoin", duplicate=0)
env.Install("build/bin", askcoin)
