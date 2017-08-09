#include <unistd.h>
#include <unordered_map>
#include <fcntl.h>
#include <sys/stat.h>
#include "fly/init.hpp"
#include "fly/net/server.hpp"
#include "fly/base/logger.hpp"
#include <openssl/err.h>
#include <openssl/rand.h>
#include "support/cleanse.h"
#include "crypto/sha512.h"
#include "hash.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "compat/sanity.h"
#include <secp256k1.h>
//#include <secp256k1_recovery.h>

using namespace std::placeholders;
static secp256k1_context* secp256k1_context_sign = NULL;
secp256k1_context* secp256k1_context_verify = NULL;

/** Users of this module must hold an ECCVerifyHandle. The constructor and
 *  destructor of these are not allowed to run in parallel, though. */
class ECCVerifyHandle
{
    static int refcount;

public:
    ECCVerifyHandle();
    ~ECCVerifyHandle();
};

static const ssize_t NUM_OS_RANDOM_BYTES = 32;
static std::unique_ptr<ECCVerifyHandle> globalVerifyHandle;


/* static */ int ECCVerifyHandle::refcount = 0;

ECCVerifyHandle::ECCVerifyHandle()
{
    if (refcount == 0) {
        assert(secp256k1_context_verify == NULL);
        secp256k1_context_verify = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        assert(secp256k1_context_verify != NULL);
    }
    refcount++;
}

ECCVerifyHandle::~ECCVerifyHandle()
{
    refcount--;
    if (refcount == 0) {
        assert(secp256k1_context_verify != NULL);
        secp256k1_context_destroy(secp256k1_context_verify);
        secp256k1_context_verify = NULL;
    }
}


static void RandFailure()
{
    //LogPrintf("Failed to read randomness, aborting\n");
    abort();
}


#ifndef WIN32
/** Fallback: get 32 bytes of system entropy from /dev/urandom. The most
 * compatible way to get cryptographic randomness on UNIX-ish platforms.
 */
void GetDevURandom(unsigned char *ent32)
{
    int f = open("/dev/urandom", O_RDONLY);
    if (f == -1) {
        RandFailure();
    }
    int have = 0;
    do {
        ssize_t n = read(f, ent32 + have, NUM_OS_RANDOM_BYTES - have);
        if (n <= 0 || n + have > NUM_OS_RANDOM_BYTES) {
            RandFailure();
        }
        have += n;
    } while (have < NUM_OS_RANDOM_BYTES);
    close(f);
}
#endif


void GetRandBytes(unsigned char* buf, int num)
{
    if (RAND_bytes(buf, num) != 1) {
        RandFailure();
    }
}



static inline int64_t GetPerformanceCounter()
{
    // Read the hardware time stamp counter when available.
    // See https://en.wikipedia.org/wiki/Time_Stamp_Counter for more information.
#if defined(_MSC_VER) && (defined(_M_IX86) || defined(_M_X64))
    return __rdtsc();
#elif !defined(_MSC_VER) && defined(__i386__)
    uint64_t r = 0;
    __asm__ volatile ("rdtsc" : "=A"(r)); // Constrain the r variable to the eax:edx pair.
    return r;
#elif !defined(_MSC_VER) && (defined(__x86_64__) || defined(__amd64__))
    uint64_t r1 = 0, r2 = 0;
    __asm__ volatile ("rdtsc" : "=a"(r1), "=d"(r2)); // Constrain r1 to rax and r2 to rdx.
    return (r2 << 32) | r1;
#else
    // Fall back to using C++11 clock (usually microsecond or nanosecond precision)
    return std::chrono::high_resolution_clock::now().time_since_epoch().count();
#endif
}

static std::mutex cs_rng_state;
static unsigned char rng_state[32] = {0};
static uint64_t rng_counter = 0;


static void AddDataToRng(void* data, size_t len) {
    CSHA512 hasher;
    hasher.Write((const unsigned char*)&len, sizeof(len));
    hasher.Write((const unsigned char*)data, len);
    unsigned char buf[64];
    {
        std::unique_lock<std::mutex> lock(cs_rng_state);
        hasher.Write(rng_state, sizeof(rng_state));
        hasher.Write((const unsigned char*)&rng_counter, sizeof(rng_counter));
        ++rng_counter;
        hasher.Finalize(buf);
        memcpy(rng_state, buf + 32, 32);
    }
    memory_cleanse(buf, 64);
}


void RandAddSeedSleep()
{
    int64_t nPerfCounter1 = GetPerformanceCounter();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    int64_t nPerfCounter2 = GetPerformanceCounter();

    // Combine with and update state
    AddDataToRng(&nPerfCounter1, sizeof(nPerfCounter1));
    AddDataToRng(&nPerfCounter2, sizeof(nPerfCounter2));

    memory_cleanse(&nPerfCounter1, sizeof(nPerfCounter1));
    memory_cleanse(&nPerfCounter2, sizeof(nPerfCounter2));
}

/** Get 32 bytes of system entropy. */
void GetOSRand(unsigned char *ent32)
{
#if defined(WIN32)
    HCRYPTPROV hProvider;
    int ret = CryptAcquireContextW(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    if (!ret) {
        RandFailure();
    }
    ret = CryptGenRandom(hProvider, NUM_OS_RANDOM_BYTES, ent32);
    if (!ret) {
        RandFailure();
    }
    CryptReleaseContext(hProvider, 0);
#elif defined(HAVE_SYS_GETRANDOM)
    /* Linux. From the getrandom(2) man page:
     * "If the urandom source has been initialized, reads of up to 256 bytes
     * will always return as many bytes as requested and will not be
     * interrupted by signals."
     */
    int rv = syscall(SYS_getrandom, ent32, NUM_OS_RANDOM_BYTES, 0);
    if (rv != NUM_OS_RANDOM_BYTES) {
        if (rv < 0 && errno == ENOSYS) {
            /* Fallback for kernel <3.17: the return value will be -1 and errno
             * ENOSYS if the syscall is not available, in that case fall back
             * to /dev/urandom.
             */
            GetDevURandom(ent32);
        } else {
            RandFailure();
        }
    }
#elif defined(HAVE_GETENTROPY)
    /* On OpenBSD this can return up to 256 bytes of entropy, will return an
     * error if more are requested.
     * The call cannot return less than the requested number of bytes.
     */
    if (getentropy(ent32, NUM_OS_RANDOM_BYTES) != 0) {
        RandFailure();
    }
#elif defined(HAVE_SYSCTL_ARND)
    /* FreeBSD and similar. It is possible for the call to return less
     * bytes than requested, so need to read in a loop.
     */
    static const int name[2] = {CTL_KERN, KERN_ARND};
    int have = 0;
    do {
        size_t len = NUM_OS_RANDOM_BYTES - have;
        if (sysctl(name, ARRAYLEN(name), ent32 + have, &len, NULL, 0) != 0) {
            RandFailure();
        }
        have += len;
    } while (have < NUM_OS_RANDOM_BYTES);
#else
    /* Fall back to /dev/urandom if there is no specific method implemented to
     * get system entropy for this OS.
     */
    GetDevURandom(ent32);
#endif
}


void RandAddSeed()
{
    // Seed with CPU performance counter
    int64_t nCounter = GetPerformanceCounter();
    RAND_add(&nCounter, sizeof(nCounter), 1.5);
    memory_cleanse((void*)&nCounter, sizeof(nCounter));
}

static void RandAddSeedPerfmon()
{
    RandAddSeed();
}

void GetStrongRandBytes(unsigned char* out, int num)
{
    assert(num <= 32);
    CSHA512 hasher;
    unsigned char buf[64];

    // First source: OpenSSL's RNG
    RandAddSeedPerfmon();
    GetRandBytes(buf, 32);
    hasher.Write(buf, 32);

    // Second source: OS RNG
    GetOSRand(buf);
    hasher.Write(buf, 32);

    // Combine with and update state
    {
        std::unique_lock<std::mutex> lock(cs_rng_state);
        hasher.Write(rng_state, sizeof(rng_state));
        hasher.Write((const unsigned char*)&rng_counter, sizeof(rng_counter));
        ++rng_counter;
        hasher.Finalize(buf);
        memcpy(rng_state, buf + 32, 32);
    }

    // Produce output
    memcpy(out, buf, num);
    memory_cleanse(buf, 64);
}

bool Check(const unsigned char *vch)
{
    return secp256k1_ec_seckey_verify(secp256k1_context_sign, vch);
}


/** This function is taken from the libsecp256k1 distribution and implements
 *  DER parsing for ECDSA signatures, while supporting an arbitrary subset of
 *  format violations.
 *
 *  Supported violations include negative integers, excessive padding, garbage
 *  at the end, and overly long length descriptors. This is safe to use in
 *  Bitcoin because since the activation of BIP66, signatures are verified to be
 *  strict DER before being passed to this module, and we know it supports all
 *  violations present in the blockchain before that point.
 */
static int ecdsa_signature_parse_der_lax(const secp256k1_context* ctx, secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen) {
    size_t rpos, rlen, spos, slen;
    size_t pos = 0;
    size_t lenbyte;
    unsigned char tmpsig[64] = {0};
    int overflow = 0;

    /* Hack to initialize sig with a correctly-parsed but invalid signature. */
    secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);

    /* Sequence tag byte */
    if (pos == inputlen || input[pos] != 0x30) {
        return 0;
    }
    pos++;

    /* Sequence length bytes */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (pos + lenbyte > inputlen) {
            return 0;
        }
        pos += lenbyte;
    }

    /* Integer tag byte for R */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for R */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (pos + lenbyte > inputlen) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        if (lenbyte >= sizeof(size_t)) {
            return 0;
        }
        rlen = 0;
        while (lenbyte > 0) {
            rlen = (rlen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        rlen = lenbyte;
    }
    if (rlen > inputlen - pos) {
        return 0;
    }
    rpos = pos;
    pos += rlen;

    /* Integer tag byte for S */
    if (pos == inputlen || input[pos] != 0x02) {
        return 0;
    }
    pos++;

    /* Integer length for S */
    if (pos == inputlen) {
        return 0;
    }
    lenbyte = input[pos++];
    if (lenbyte & 0x80) {
        lenbyte -= 0x80;
        if (pos + lenbyte > inputlen) {
            return 0;
        }
        while (lenbyte > 0 && input[pos] == 0) {
            pos++;
            lenbyte--;
        }
        if (lenbyte >= sizeof(size_t)) {
            return 0;
        }
        slen = 0;
        while (lenbyte > 0) {
            slen = (slen << 8) + input[pos];
            pos++;
            lenbyte--;
        }
    } else {
        slen = lenbyte;
    }
    if (slen > inputlen - pos) {
        return 0;
    }
    spos = pos;
    pos += slen;

    /* Ignore leading zeroes in R */
    while (rlen > 0 && input[rpos] == 0) {
        rlen--;
        rpos++;
    }
    /* Copy R value */
    if (rlen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 32 - rlen, input + rpos, rlen);
    }

    /* Ignore leading zeroes in S */
    while (slen > 0 && input[spos] == 0) {
        slen--;
        spos++;
    }
    /* Copy S value */
    if (slen > 32) {
        overflow = 1;
    } else {
        memcpy(tmpsig + 64 - slen, input + spos, slen);
    }

    if (!overflow) {
        overflow = !secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    if (overflow) {
        /* Overwrite the result again with a correctly-parsed but invalid
           signature if parsing failed. */
        memset(tmpsig, 0, 64);
        secp256k1_ecdsa_signature_parse_compact(ctx, sig, tmpsig);
    }
    return 1;
}



/** A reference to a CKey: the Hash160 of its serialized public key */
class CKeyID : public uint160
{
public:
    CKeyID() : uint160() {}
    CKeyID(const uint160& in) : uint160(in) {}
};

typedef uint256 ChainCode;

/** An encapsulated public key. */
class CPubKey
{
private:

    /**
     * Just store the serialized data.
     * Its length can very cheaply be computed from the first byte.
     */
    unsigned char vch[65];

    //! Compute the length of a pubkey with a given first byte.
    unsigned int static GetLen(unsigned char chHeader)
    {
        if (chHeader == 2 || chHeader == 3)
            return 33;
        if (chHeader == 4 || chHeader == 6 || chHeader == 7)
            return 65;
        return 0;
    }

    //! Set this key data to be invalid
    void Invalidate()
    {
        vch[0] = 0xFF;
    }

public:
    //! Construct an invalid public key.
    CPubKey()
    {
        Invalidate();
    }

    //! Initialize a public key using begin/end iterators to byte data.
    template <typename T>
    void Set(const T pbegin, const T pend)
    {
        int len = pend == pbegin ? 0 : GetLen(pbegin[0]);
        if (len && len == (pend - pbegin))
            memcpy(vch, (unsigned char*)&pbegin[0], len);
        else
            Invalidate();
    }

    //! Construct a public key using begin/end iterators to byte data.
    template <typename T>
    CPubKey(const T pbegin, const T pend)
    {
        Set(pbegin, pend);
    }

    //! Construct a public key from a byte vector.
    CPubKey(const std::vector<unsigned char>& _vch)
    {
        Set(_vch.begin(), _vch.end());
    }

    //! Simple read-only vector-like interface to the pubkey data.
    unsigned int size() const { return GetLen(vch[0]); }
    const unsigned char* begin() const { return vch; }
    const unsigned char* end() const { return vch + size(); }
    const unsigned char& operator[](unsigned int pos) const { return vch[pos]; }

    //! Comparator implementation.
    friend bool operator==(const CPubKey& a, const CPubKey& b)
    {
        return a.vch[0] == b.vch[0] &&
               memcmp(a.vch, b.vch, a.size()) == 0;
    }
    friend bool operator!=(const CPubKey& a, const CPubKey& b)
    {
        return !(a == b);
    }
    friend bool operator<(const CPubKey& a, const CPubKey& b)
    {
        return a.vch[0] < b.vch[0] ||
               (a.vch[0] == b.vch[0] && memcmp(a.vch, b.vch, a.size()) < 0);
    }

    // //! Implement serialization, as if this was a byte vector.
    // template <typename Stream>
    // void Serialize(Stream& s) const
    // {
    //     unsigned int len = size();
    //     ::WriteCompactSize(s, len);
    //     s.write((char*)vch, len);
    // }
    // template <typename Stream>
    // void Unserialize(Stream& s)
    // {
    //     unsigned int len = ::ReadCompactSize(s);
    //     if (len <= 65) {
    //         s.read((char*)vch, len);
    //     } else {
    //         // invalid pubkey, skip available data
    //         char dummy;
    //         while (len--)
    //             s.read(&dummy, 1);
    //         Invalidate();
    //     }
    // }

    //! Get the KeyID of this public key (hash of its serialization)
    CKeyID GetID() const
    {
        return CKeyID(Hash160(vch, vch + size()));
    }

    //! Get the 256-bit hash of this public key.
    uint256 GetHash() const
    {
        return Hash(vch, vch + size());
    }

    /*
     * Check syntactic correctness.
     *
     * Note that this is consensus critical as CheckSig() calls it!
     */
    bool IsValid() const
    {
        return size() > 0;
    }

    //! fully validate whether this is a valid public key (more expensive than IsValid())
    bool IsFullyValid() const;

    //! Check whether this is a compressed public key.
    bool IsCompressed() const
    {
        return size() == 33;
    }

    /**
     * Verify a DER signature (~72 bytes).
     * If this public key is not fully valid, the return value will be false.
     */
    bool Verify(const uint256 &hash, const std::vector<unsigned char>& vchSig) const {
        if (!IsValid())
            return false;
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature sig;
        if (!secp256k1_ec_pubkey_parse(secp256k1_context_verify, &pubkey, &(*this)[0], size())) {
            return false;
        }
        if (vchSig.size() == 0) {
            return false;
        }
        if (!ecdsa_signature_parse_der_lax(secp256k1_context_verify, &sig, &vchSig[0], vchSig.size())) {
            return false;
        }
        /* libsecp256k1's ECDSA verification requires lower-S signatures, which have
         * not historically been enforced in Bitcoin, so normalize them first. */
        secp256k1_ecdsa_signature_normalize(secp256k1_context_verify, &sig, &sig);
        return secp256k1_ecdsa_verify(secp256k1_context_verify, &sig, hash.begin(), &pubkey);
    }


    /**
     * Check whether a signature is normalized (lower-S).
     */
    static bool CheckLowS(const std::vector<unsigned char>& vchSig);

    //! Recover a public key from a compact signature.
    bool RecoverCompact(const uint256& hash, const std::vector<unsigned char>& vchSig);

    //! Turn this public key into an uncompressed public key.
    bool Decompress();

    //! Derive BIP32 child pubkey.
    bool Derive(CPubKey& pubkeyChild, ChainCode &ccChild, unsigned int nChild, const ChainCode& cc) const;
};


class CKey
{
public:
    //! Construct an invalid private key.
    CKey() : fValid(false), fCompressed(false)
    {
        // Important: vch must be 32 bytes in length to not break serialization
        keydata.resize(32);
    }

    bool fValid;

    //! Whether the public key corresponding to this private key is (to be) compressed.
    bool fCompressed;

    //! The actual byte data
    std::vector<unsigned char> keydata;

    void MakeNewKey(bool fCompressedIn) {
        do {
            GetStrongRandBytes(keydata.data(), keydata.size());
        } while (!Check(keydata.data()));
        fValid = true;
        fCompressed = fCompressedIn;
    }    

    //! Simple read-only vector-like interface.
    unsigned int size() const { return (fValid ? keydata.size() : 0); }
    const unsigned char* begin() const { return keydata.data(); }
    const unsigned char* end() const { return keydata.data() + size(); }

    CPubKey GetPubKey() const {
        assert(fValid);
        secp256k1_pubkey pubkey;
        size_t clen = 65;
        CPubKey result;
        int ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, begin());
        assert(ret);
        secp256k1_ec_pubkey_serialize(secp256k1_context_sign, (unsigned char*)result.begin(), &clen, &pubkey, fCompressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);
        assert(result.size() == clen);
        assert(result.IsValid());
        return result;
    }

    bool VerifyPubKey(const CPubKey& pubkey) const {
        if (pubkey.IsCompressed() != fCompressed) {
            return false;
        }
        unsigned char rnd[8];
        std::string str = "Bitcoin key verification\n";
        GetRandBytes(rnd, sizeof(rnd));
        uint256 hash;
        CHash256().Write((unsigned char*)str.data(), str.size()).Write(rnd, sizeof(rnd)).Finalize(hash.begin());
        std::vector<unsigned char> vchSig;
        Sign(hash, vchSig);
        return pubkey.Verify(hash, vchSig);
    }

    bool Sign(const uint256 &hash, std::vector<unsigned char>& vchSig, uint32_t test_case = 0) const {
        if (!fValid)
            return false;
        vchSig.resize(72);
        size_t nSigLen = 72;
        unsigned char extra_entropy[32] = {0};
        WriteLE32(extra_entropy, test_case);
        secp256k1_ecdsa_signature sig;
        int ret = secp256k1_ecdsa_sign(secp256k1_context_sign, &sig, hash.begin(), begin(), secp256k1_nonce_function_rfc6979, test_case ? extra_entropy : NULL);
        assert(ret);
        secp256k1_ecdsa_signature_serialize_der(secp256k1_context_sign, (unsigned char*)&vchSig[0], &nSigLen, &sig);
        vchSig.resize(nSigLen);
        LOG_INFO("siglen: %u", nSigLen);
        
        return true;
    }

};

bool ECC_InitSanityCheck() {
    
    // CKey key;
    // key.MakeNewKey(true);
    // CPubKey pubkey = key.GetPubKey();
    // return key.VerifyPubKey(pubkey);
    
    std::vector<unsigned char> vec1 = {0x04,0xa5,0xc1,0x77,0xb9,0xe4,0xb5,0xda,0x15,0xc5,0x0e,0x75,0x35,0xbf,0xdd,0xac,0xe5,0x91,0x88,0x32,0xb6,0x87,0x8d,0xac,0xab,0x53,0x51,0xe3,0x5e,0x90,0x17,0xda,0x80,0x6d,0x08,0x87,0x31,0xba,0x78,0x3d,0x04,0x27,0xbb,0x68,0x94,0x01,0x47,0x92,0xe8,0x4e,0x71,0xe2,0xca,0xd0,0x11,0x26,0x01,0x0c,0x4c,0x87,0x97,0xb4,0x2d,0xb8,0x29};
    
    CPubKey pub(vec1);
    std::vector<unsigned char> vec2 = {0x30,0x45,0x02,0x20,0x1f,0x02,0x39,0x9a,0xae,0x46,0x2c,0x09,0xd5,0x24,0x84,0x0c,0x88,0xc1,0xd5,0x06,0xea,0x7c,0x6c,0xe8,0x6f,0x71,0x03,0x29,0xbe,0x52,0x12,0xc8,0xc1,0x60,0x0e,0xd9,0x02,0x21,0x00,0x83,0x77,0xe8,0x93,0xd9,0xa4,0x74,0xc6,0x4b,0x37,0xb7,0x70,0xf5,0x85,0xa8,0x37,0xe3,0x3d,0x36,0xa1,0xf6,0xf2,0x73,0xfa,0x92,0xb4,0xd0,0x40,0x1e,0x9d,0xb7,0x26};
    
    uint256 msg({0x31,0xcd,0xa2,0xab,0x84,0x52,0xa3,0x3d,0x1f,0x25,0x41,0x2e,0x56,0x8c,0x71,0x6d,0x5b,0xb8,0x01,0x45,0xf6,0xad,0xd2,0x6f,0x5f,0x24,0x70,0xf4,0x64,0x22,0xe6,0xf7});
    
    if(pub.Verify(msg, vec2)) {
        LOG_INFO("sign success.............");
        return true;
    }
    LOG_ERROR("sign failed............");
    
    return false;
}


bool Random_SanityCheck()
{
    uint64_t start = GetPerformanceCounter();

    /* This does not measure the quality of randomness, but it does test that
     * OSRandom() overwrites all 32 bytes of the output given a maximum
     * number of tries.
     */
    static const ssize_t MAX_TRIES = 1024;
    uint8_t data[NUM_OS_RANDOM_BYTES];
    bool overwritten[NUM_OS_RANDOM_BYTES] = {}; /* Tracks which bytes have been overwritten at least once */
    int num_overwritten;
    int tries = 0;
    /* Loop until all bytes have been overwritten at least once, or max number tries reached */
    do {
        memset(data, 0, NUM_OS_RANDOM_BYTES);
        GetOSRand(data);
        for (int x=0; x < NUM_OS_RANDOM_BYTES; ++x) {
            overwritten[x] |= (data[x] != 0);
        }

        num_overwritten = 0;
        for (int x=0; x < NUM_OS_RANDOM_BYTES; ++x) {
            if (overwritten[x]) {
                num_overwritten += 1;
            }
        }

        tries += 1;
    } while (num_overwritten < NUM_OS_RANDOM_BYTES && tries < MAX_TRIES);
    if (num_overwritten != NUM_OS_RANDOM_BYTES) return false; /* If this failed, bailed out after too many tries */

    // Check that GetPerformanceCounter increases at least during a GetOSRand() call + 1ms sleep.
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
    uint64_t stop = GetPerformanceCounter();
    if (stop == start) return false;

    // We called GetPerformanceCounter. Use it as entropy.
    RAND_add((const unsigned char*)&start, sizeof(start), 1);
    RAND_add((const unsigned char*)&stop, sizeof(stop), 1);

    return true;
}


/** Sanity checks
 *  Ensure that Bitcoin is running in a usable environment with all
 *  necessary library support.
 */
bool InitSanityCheck(void)
{
    if(!ECC_InitSanityCheck()) {
        //InitError("Elliptic curve cryptography sanity check failure. Aborting.");
        return false;
    }

    if (!glibc_sanity_test() || !glibcxx_sanity_test())
        return false;

    if (!Random_SanityCheck()) {
        //InitError("OS cryptographic RNG sanity check failure. Aborting.");
        return false;
    }

    return true;
}

void ECC_Start() {
    assert(secp256k1_context_sign == NULL);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    assert(ctx != NULL);

    {
        // Pass in a random blinding seed to the secp256k1 context.
        std::vector<unsigned char> vseed(32);
        GetRandBytes(vseed.data(), 32);
        bool ret = secp256k1_context_randomize(ctx, vseed.data());
        assert(ret);
    }

    secp256k1_context_sign = ctx;
}

void ECC_Stop() {
    secp256k1_context *ctx = secp256k1_context_sign;
    secp256k1_context_sign = NULL;

    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
}


bool AppInitSanityChecks()
{
    // ********************************************************* Step 4: sanity checks

    // Initialize elliptic curve code
    ECC_Start();
    globalVerifyHandle.reset(new ECCVerifyHandle());

    // Sanity check
    if (!InitSanityCheck())
        return false;
    return true;
    
        //return InitError(strprintf(_("Initialization sanity check failed. %s is shutting down."), _(PACKAGE_NAME)));

    // Probe the data directory lock to give an early error message, if possible
    //return LockDataDirectory(true);
        
}

using fly::net::Wsock;
#include <iostream>
using namespace std;


#include "leveldb/db.h"

class Askcoin : public fly::base::Singleton<Askcoin>
{
public:
    bool allow(std::shared_ptr<fly::net::Connection<Wsock>> connection)
    {
        return true;
    }
    
    void init(std::shared_ptr<fly::net::Connection<Wsock>> connection)
    {
        std::lock_guard<std::mutex> guard(m_mutex);
        m_connections[connection->id()] = connection;
        LOG_INFO("connection count: %u", m_connections.size());
    }
    
    void dispatch(std::unique_ptr<fly::net::Message<Wsock>> message)
    {
        std::shared_ptr<fly::net::Connection<Wsock>> connection = message->get_connection();
        const fly::net::Addr &addr = connection->peer_addr();
        LOG_INFO("recv message from %s:%d raw_data: %s", addr.m_host.c_str(), addr.m_port, message->raw_data().c_str());
    }
    
    void close(std::shared_ptr<fly::net::Connection<Wsock>> connection)
    {
        LOG_INFO("close connection from %s:%d", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
        std::lock_guard<std::mutex> guard(m_mutex);
        m_connections.erase(connection->id());
        LOG_INFO("connection count: %u", m_connections.size());
    }
    
    void be_closed(std::shared_ptr<fly::net::Connection<Wsock>> connection)
    {
        LOG_INFO("connection from %s:%d be closed", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
        std::lock_guard<std::mutex> guard(m_mutex);
        m_connections.erase(connection->id());
        LOG_INFO("connection count: %u", m_connections.size());
    }
    
    void main()
    {
        //init library
        fly::init();

        fly::base::Logger::instance()->init(fly::base::DEBUG, "server", "./log/");
        
        if (!AppInitSanityChecks())
        {
            // InitError will have been called with detailed error, which ends up on console
            LOG_FATAL("sanity check failed");
            exit(EXIT_FAILURE);
        }


        LOG_INFO("sanity check ok");
        leveldb::DB *db;
        leveldb::Options options;
        options.create_if_missing = true;
        //options.error_if_exists = true;

        std::string tstr = "abcdefg";
        cout << tstr.c_str() << " size: " << tstr.size() << " length: " << tstr.length() << endl;
        tstr[3] = '\0';
        cout << tstr.c_str() << " size: " << tstr.size() << " length: " << tstr.length() << endl;
        
        
        leveldb::Status status = leveldb::DB::Open(options, "./db", &db);
        std::string res = status.ToString();
        LOG_INFO("status str: %s", res.c_str());

        std::string val;
        leveldb::Status s;
        //s = db->Put(leveldb::WriteOptions(), "block123", "val is 123");
        
        // if(s.ok()) s = db->Get(leveldb::ReadOptions(), "block456", &val);
        // else
        // {
        //     LOG_INFO("write first failed: %s", s.ToString().c_str());
        // }
        // if(s.ok()) s = db->Put(leveldb::WriteOptions(), "block456", val);
        // else
        // {
        //     LOG_INFO("get failed: %s", s.ToString().c_str());
        // }
        
        if(s.ok()) s = db->Delete(leveldb::WriteOptions(), "block456");
        else
        {
            LOG_INFO("put failed: %s", s.ToString().c_str());
        }

        if(!s.ok())
        {
            LOG_INFO("delete failed: %s", s.ToString().c_str());
        }
        
        assert(status.ok());

        return;
        
        
        
        //test tcp server
        std::unique_ptr<fly::net::Server<Wsock>> server(new fly::net::Server<Wsock>(fly::net::Addr("127.0.0.1", 8899),
                                                                      std::bind(&Askcoin::allow, this, _1),
                                                                      std::bind(&Askcoin::init, this, _1),
                                                                      std::bind(&Askcoin::dispatch, this, _1),
                                                                      std::bind(&Askcoin::close, this, _1),
                                                                      std::bind(&Askcoin::be_closed, this, _1)));

        if(server->start())
        {
            LOG_INFO("start server ok!");
            server->wait();
        }
        else
        {
            LOG_FATAL("start server failed");
        }
    }
    
private:
    std::unordered_map<uint64, std::shared_ptr<fly::net::Connection<Wsock>>> m_connections;
    std::mutex m_mutex;
};

int main()
{
    Askcoin::instance()->main();
}
