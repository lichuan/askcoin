#include "leveldb/db.h"
#include "leveldb/comparator.h"
#include "fly/base/logger.hpp"
#include "blockchain.hpp"
#include "key.h"
#include "utilstrencodings.h"
#include "cryptopp/sha.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

Blockchain::Blockchain()
{
}

Blockchain::~Blockchain()
{
}

class DB_Comp : public leveldb::Comparator
{
public:
    int Compare(const leveldb::Slice &a, const leveldb::Slice &b) const
    {
        uint64 u_a, u_b;
        fly::base::string_to(a.data(), u_a);
        fly::base::string_to(b.data(), u_b);

        if(u_a < u_b)
        {
            return -1;
        }

        if(u_a > u_b)
        {
            return 1;
        }

        return 0;
    }

    const char* Name() const
    {
        return "DB_Comp";
    }

    void FindShortestSeparator(std::string* start, const leveldb::Slice& limit) const {}
    void FindShortSuccessor(std::string* key) const {}
};

bool Blockchain::load(std::string db_path)
{
    leveldb::DB *db;
    DB_Comp comp;
    leveldb::Options options;
    options.comparator = &comp;
    options.create_if_missing = true;
    leveldb::Status s = leveldb::DB::Open(options, db_path, &db);

    if(!s.ok())
    {
        CONSOLE_LOG_FATAL("open leveldb failed: %s", s.ToString().c_str());

        return false;
    }

    std::string block_0;
    s = db->Get(leveldb::ReadOptions(), "0", &block_0);
    
    if(!s.ok())
    {
        if(!s.IsNotFound())
        {
            CONSOLE_LOG_FATAL("read block_0 from leveldb failed: %s", s.ToString().c_str());

            return false;
        }

        std::string genesis_block_data = "{\"author\":{\"name\":\"Chuan Li\",\"country\":\"China\",\"github\":\"https://github.com/lichuan\",\"mail\":\"308831759@qq.com\",\"belief\":\"In the beginning, God created the heavens and the earth.\"},\"version\":1000,\"intro\":\"This coin is a gift for those who love freedom.\",\"total\":10000000000,\"decimal\":8,\"init_account\":{\"account\":\"lichuan\",\"address\":\"VH1D4WKijCgr9YQtHRlpenbUJlo=\"},\"init_witness\":\"lichuan\",\"reserve_fund_account\":\"reserve_fund\",\"id\":0}";
        std::string genesis_block_hash = coin_hash(genesis_block_data.c_str(), genesis_block_data.length());
        CONSOLE_LOG_INFO("genesis_block_hash is: %s", genesis_block_hash.c_str());
        rapidjson::Document data_doc;
        data_doc.Parse(genesis_block_data.c_str());

        if(data_doc.HasParseError())
        {
            return false;
        }
        
        rapidjson::Document doc;
        doc.SetObject();
        rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
        doc.AddMember("data", data_doc, allocator);
        doc.AddMember("hash", rapidjson::StringRef(genesis_block_hash.c_str()), allocator);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        doc.Accept(writer);
        CONSOLE_LOG_INFO("docbuffer:%s, size:%u", buffer.GetString(), buffer.GetSize());
        s = db->Put(leveldb::WriteOptions(), "0", buffer.GetString());

        if(!s.ok())
        {
            return false;
        }

        //try again
        s = db->Get(leveldb::ReadOptions(), "0", &block_0);

        if(!s.ok())
        {
            return false;
        }
        
        // CKey key;
        // key.MakeNewKey(false);
        // CPubKey pubkey = key.GetPubKey();
        // std::string key_b64 = fly::base::base64_encode(key.begin(), key.size());
        // std::string pubkey_b64 = fly::base::base64_encode(pubkey.begin(), pubkey.size());
        // std::string addr = coin_addr(pubkey.begin(), pubkey.size());
        // CONSOLE_LOG_INFO("key: %s, pubkey: %s, addr: %s", key_b64.c_str(), pubkey_b64.c_str(), addr.c_str());

        // std::string k1 = "oZt/88+Bw/oOoNLL7L2r6piRtdRj+Qh7mH4P+57tG4g=";
        // char privk[32];
        // fly::base::base64_decode(k1.c_str(), k1.size(), privk, 32);
        // CKey ck1;
        // ck1.Set(privk, privk + 32, false);
        // CPubKey pubk1 = ck1.GetPubKey();
        // std::string pubk_64 = fly::base::base64_encode(pubk1.begin(), pubk1.size());
        // CONSOLE_LOG_INFO("new pubkey: %s", pubk_64.c_str());
    }

    const char *block_0_str = block_0.c_str();
    CONSOLE_LOG_INFO("block_0 is: %s", block_0_str);
    rapidjson::Document doc;
    doc.Parse(block_0_str);

    if(doc.HasParseError())
    {
        CONSOLE_LOG_FATAL("parse leveldb block 0 failed, data: %s, reason: %s", block_0_str, GetParseError_En(doc.GetParseError()));

        return false;
    }

    if(!doc.HasMember("data"))
    {
        CONSOLE_LOG_FATAL("parse leveldb block 0 failed, block haven't version field, data: %s", block_0_str);
        
        return false;
    }

    if(!doc.HasMember("hash"))
    {
        CONSOLE_LOG_FATAL("parse leveldb block 0 failed, block haven't hash field, data: %s", block_0_str);
        
        return false;
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc["data"].Accept(writer);
    std::string block_hash = doc["hash"].GetString();
    std::string block_hash_verify = coin_hash(buffer.GetString(), buffer.GetSize());
    CONSOLE_LOG_INFO("block_hash: %s, block_hash_verify: %s", block_hash.c_str(), block_hash_verify.c_str());
    
    if(block_hash != block_hash_verify)
    {
        CONSOLE_LOG_FATAL("verify block 0 hash failed");

        return false;
    }
    
    uint64 prev_block_id = 0;
    leveldb::Iterator *it = db->NewIterator(leveldb::ReadOptions());
    
    for(it->Seek("1"); it->Valid(); it->Next())
    {
        std::string k = it->key().ToString();
        uint64 block_id;
        fly::base::string_to(k.c_str(), block_id);
        std::string data = it->value().ToString();
        rapidjson::Document doc;
        doc.Parse(data.c_str());

        if(doc.HasParseError())
        {
            CONSOLE_LOG_FATAL("parse leveldb block data failed, block_id: %lu, data: %s, reason: %s", block_id, data.c_str(), GetParseError_En(doc.GetParseError()));
            
            return false;
        }
        
        if(!doc.HasMember("data"))
        {
            CONSOLE_LOG_FATAL("parse leveldb block data failed, block haven't version field, block_id: %lu, data: %s", block_id, data.c_str());

            return false;
        }

        if(!doc.HasMember("hash"))
        {
            CONSOLE_LOG_FATAL("parse leveldb block data failed, block haven't hash field, block_id: %lu, data: %s", block_id, data.c_str());

            return false;
        }

        std::string block_data = doc["data"].GetString();
        std::string block_hash = doc["hash"].GetString();
        
        if(block_id == 0)
        {
            //genesis
            
        }
        else if(block_id != prev_block_id + 1)
        {
            CONSOLE_LOG_FATAL("leveldb block id doesn't continuously, block_id: %lu, prev_block_id: %lu", block_id, prev_block_id);
            
            return false;
        }

        CONSOLE_LOG_INFO("key: %s, num: %lu, val: %s", it->key().ToString().c_str(), block_id, it->value().ToString().c_str());
    }
    
    //s = db->Get(leveldb::ReadOptions(), "bliiock22_count", &val);
    //s = db->Get(leveldb::ReadOptions(), "block_count", &val);
    //s = db->Delete(leveldb::WriteOptions(), "block_couniiwwwwwwwwwwwwt");
    
    std::vector<unsigned char> vec1 = {0x04,0xa5,0xc1,0x77,0xb9,0xe4,0xb5,0xda,0x15,0xc5,0x0e,0x75,0x35,0xbf,0xdd,0xac,0xe5,0x91,0x88,0x32,0xb6,0x87,0x8d,0xac,0xab,0x53,0x51,0xe3,0x5e,0x90,0x17,0xda,0x80,0x6d,0x08,0x87,0x31,0xba,0x78,0x3d,0x04,0x27,0xbb,0x68,0x94,0x01,0x47,0x92,0xe8,0x4e,0x71,0xe2,0xca,0xd0,0x11,0x26,0x01,0x0c,0x4c,0x87,0x97,0xb4,0x2d,0xb8,0x29};
    
    CPubKey pub(vec1);
    std::vector<unsigned char> vec2 = {0x30,0x45,0x02,0x20,0x1f,0x02,0x39,0x9a,0xae,0x46,0x2c,0x09,0xd5,0x24,0x84,0x0c,0x88,0xc1,0xd5,0x06,0xea,0x7c,0x6c,0xe8,0x6f,0x71,0x03,0x29,0xbe,0x52,0x12,0xc8,0xc1,0x60,0x0e,0xd9,0x02,0x21,0x00,0x83,0x77,0xe8,0x93,0xd9,0xa4,0x74,0xc6,0x4b,0x37,0xb7,0x70,0xf5,0x85,0xa8,0x37,0xe3,0x3d,0x36,0xa1,0xf6,0xf2,0x73,0xfa,0x92,0xb4,0xd0,0x40,0x1e,0x9d,0xb7,0x26};
    
    uint256 msg({0x31,0xcd,0xa2,0xab,0x84,0x52,0xa3,0x3d,0x1f,0x25,0x41,0x2e,0x56,0x8c,0x71,0x6d,0x5b,0xb8,0x01,0x45,0xf6,0xad,0xd2,0x6f,0x5f,0x24,0x70,0xf4,0x64,0x22,0xe6,0xf7});
    
    if(!pub.Verify(msg, vec2)) {
        CONSOLE_LOG_ERROR("sign failed............");
        return false;
    }

    CONSOLE_LOG_INFO("sign success.............");

    std::string tdata = "a1232323232342342bc";
    uint160 u160 = Hash160(tdata.begin(), tdata.end());
    uint256 u256 = Hash(tdata.begin(), tdata.end());
    
    std::string b64 = EncodeBase64(u160.begin(), u160.size());
    std::string b642 = fly::base::base64_encode(u160.begin(), u160.size());
    std::string hex2 = fly::base::byte2hexstr(u160.begin(), u160.size());
    std::string hex256_2 = fly::base::byte2hexstr(u256.begin(), u256.size());
    char buf[CryptoPP::SHA256::DIGESTSIZE] = {0};
    CONSOLE_LOG_INFO("SHA256::DIGESTSIZE is: %d", CryptoPP::SHA256::DIGESTSIZE);
    
    if(!fly::base::sha256(tdata.c_str(), tdata.length(), buf, CryptoPP::SHA256::DIGESTSIZE))
    {
        CONSOLE_LOG_FATAL("fly sha256 failed!");
    }

    char s256[CSHA256::OUTPUT_SIZE] = {0};
    CSHA256().Write(tdata.c_str(), tdata.size()).Finalize(s256);
    std::string s256_hex = fly::base::byte2hexstr(s256, CSHA256::OUTPUT_SIZE);
        
    std::string hex256_fly = fly::base::byte2hexstr(buf, CryptoPP::SHA256::DIGESTSIZE);
        
    CONSOLE_LOG_INFO("hex: %s", u160.GetHex().c_str());
    CONSOLE_LOG_INFO("hex2: %s", hex2.c_str());
    CONSOLE_LOG_INFO("hex256: %s", u256.GetHex().c_str());
    CONSOLE_LOG_INFO("hex256_2: %s", hex256_2.c_str());
    CONSOLE_LOG_INFO("hex256 fly: %s", hex256_fly.c_str());
    CONSOLE_LOG_INFO("hex256 once: %s", s256_hex.c_str());
    CONSOLE_LOG_INFO("b64: %s", b64.c_str());
    CONSOLE_LOG_INFO("b642: %s", b642.c_str());
    CONSOLE_LOG_INFO("sanity check success.");

    char arr[10] = {'a','b','c',0x5,'e','f','g','h','a','a'};
    std::string str = fly::base::byte2hexstr(arr, 10);
    CONSOLE_LOG_INFO("hexstr: %s", str.c_str());

    char arr1[11] = {0};
    uint32 len = fly::base::hexstr2byte(str.c_str(), str.length(), arr1,10);
    CONSOLE_LOG_INFO("hexstr2byte: len: %d, arr1: %s, %02x", len, arr1, arr1[3]);

    std::string str1 = fly::base::base64_encode(arr1, 10);
    std::string str2 = fly::base::base64_encode(arr, 10);
    CONSOLE_LOG_INFO("str1: %s", str1.c_str());
    CONSOLE_LOG_INFO("str2: %s", str2.c_str());

    char arr2[11] = {0};
    uint32 len2 = fly::base::base64_decode(str1.c_str(), str1.length(), arr2, 10);
    CONSOLE_LOG_INFO("len2: %d arr2: %s", len2, arr2);
    
    std::string str_hash = "IJ8NTsepqQTKWi9F2xdY+76H5eiJbElFUrEBNkJu7nw=";
    std::string str_pub = "BIie7a1Jd5JMzka6rEnm5YusF896bsoE2gUfz4HPqJbPCT8RwT/yIHG2pYtRTfkEzgBRDxIyybqULA5CGDJNivw=";
    std::string str_sig = "MEYCIQCCDPBA2IMRHyNKvsH00LAH7/7bZBmK36AZeBIzSY05CQIhAOepJCA+RRY08JguV5Hx6Ht3fslDYKAc8UymzEwe1Vd7";
        
    char arr_hash[40] = {0};
    char arr_pub[70] = {0};
    char arr_sig[80] = {0};
    uint32 len_hash = fly::base::base64_decode(str_hash.c_str(), str_hash.length(), arr_hash, 40);
    CONSOLE_LOG_INFO("len_hash: %d", len_hash);
    uint32 len_pub = fly::base::base64_decode(str_pub.c_str(), str_pub.length(), arr_pub, 70);
    CONSOLE_LOG_INFO("len_pub: %d", len_pub);
    uint32 len_sig = fly::base::base64_decode(str_sig.c_str(), str_sig.length(), arr_sig, 80);
    CONSOLE_LOG_INFO("len_sig: %d", len_sig);

    std::string hex_hash = fly::base::byte2hexstr(arr_hash, 32);
    std::string hex_sig = fly::base::byte2hexstr(arr_sig, 72);
    std::string hex_pub = fly::base::byte2hexstr(arr_pub, 65);
    
    CONSOLE_LOG_INFO("arr_hash: %s", hex_hash.c_str());
    CONSOLE_LOG_INFO("arr_pub: %s", hex_pub.c_str());
    CONSOLE_LOG_INFO("arr_sig: %s", hex_sig.c_str());

    CPubKey pkey;
    pkey.Set(arr_pub, arr_pub + len_pub);
    
    if(pkey.Verify(uint256(std::vector<unsigned char>(arr_hash, arr_hash + len_hash)), std::vector<unsigned char>(arr_sig, arr_sig + len_sig)))
    {
        CONSOLE_LOG_INFO("verify ok...............");
    }
    else {
        CONSOLE_LOG_INFO("verify failed.................");
    }
        
    return true;
}
