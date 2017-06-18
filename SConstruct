import os
import copy
SetOption("random", 1)

def get_static_library_name(node):
    return os.path.basename(str(node)[:-2])[3:-2]

def get_shared_library_name(node):
    return os.path.basename(str(node)[:-2])[3:-3]

# depend library
fly = File('#depend/fly/build/bin/libfly.a')
secp256k1 = File('#depend/secp256k1/.libs/libsecp256k1.a')

libs = [
    fly,
    secp256k1,
    "ssl",
    "crypto"
]

lib_path = [
#    "#build/bin"
]

env = Environment(CCFLAGS='-g -O2 -Wall -std=c++11', LINKFLAGS='-pthread', CPPPATH=["#.", "#depend/fly/src", "#depend/fly/3rd-library/include"])
env.Replace(LIBS=libs, LIBPATH=lib_path)
Export("env")

test_server = SConscript("SConscript1", variant_dir="build/test_server", duplicate=0)
env.Install("build/bin", test_server)

# test_client = SConscript("test/SConscript2", variant_dir="build/test_client", duplicate=0)
# env.Install("build/bin", test_client)
