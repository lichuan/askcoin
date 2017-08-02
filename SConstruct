import os
import copy
SetOption("random", 1)

def get_static_library_name(node):
    return os.path.basename(str(node)[:-2])[3:-2]

def get_shared_library_name(node):
    return os.path.basename(str(node)[:-2])[3:-3]

# depend library
fly = File('#depend/fly/build/bin/libfly.a')
crypto_algorithms = File('#depend/fly/build/bin/libcrypto-algorithms.a')
secp256k1 = File('#depend/secp256k1/.libs/libsecp256k1.a')

libs = [
    crypto_algorithms,
    fly,
    secp256k1,
    "ssl",
    "crypto"
]

lib_path = [
#    "#build/bin"
]

env = Environment(CCFLAGS='-g -O2 -Wall -std=c++11', LINKFLAGS='-pthread', CPPPATH=["#src", "#depend/fly/src", "#depend/fly/depend/rapidjson/include"])
env.Replace(LIBS=libs, LIBPATH=lib_path)

Export("env")
askcoin = SConscript("src/SConscript", variant_dir="build/askcoin", duplicate=0)
env.Install("build/bin", askcoin)

# test_client = SConscript("test/SConscript", variant_dir="build/test_client", duplicate=0)
# env.Install("build/bin", test_client)
