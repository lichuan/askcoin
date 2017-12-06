import os
import copy
SetOption("random", 1)

def get_static_library_name(node):
    return os.path.basename(str(node)[:-2])[3:-2]

def get_shared_library_name(node):
    return os.path.basename(str(node)[:-2])[3:-3]

# depend library

env = Environment(CCFLAGS='-g -O2 -Wall -std=c++11', LINKFLAGS='-pthread', CPPPATH=[
    "#src", "#depend/fly/src",
    "#depend/leveldb/include",
    "#depend/fly/depend/rapidjson/include",
    "#depend/secp256k1/include"
    ])

fly = File('#depend/fly/build/bin/libfly.a')
cryptopp = File('#depend/fly/depend/cryptopp/libcryptopp.a')
secp256k1 = File('#depend/secp256k1/.libs/libsecp256k1.a')
leveldb = File('#depend/leveldb/out-static/libleveldb.a')
env.Command([fly, cryptopp], None, "cd depend/fly && scons")
env.Command(secp256k1, None, "cd depend/secp256k1 && ./autogen.sh && ./configure --enable-module-recovery && make clean && make")
env.Command(leveldb, None, "cd depend/leveldb && make")

libs = [
    cryptopp,
    fly,
    secp256k1,
    leveldb,
    "crypto",
]

lib_path = [
]

env.Replace(LIBS=libs, LIBPATH=lib_path)

Export("env")
askcoin = SConscript("src/SConscript", variant_dir="build/askcoin", duplicate=0)
env.Install("build/bin", askcoin)

# test_client = SConscript("test/SConscript", variant_dir="build/test_client", duplicate=0)
# env.Install("build/bin", test_client)
