#include "leveldb/db.h"
#include "leveldb/comparator.h"
#include "fly/base/logger.hpp"
#include "blockchain.hpp"
#include "key.h"
#include "version.hpp"
#include "utilstrencodings.h"
#include "cryptopp/sha.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include <unistd.h>

Blockchain::Blockchain()
{
}

Blockchain::~Blockchain()
{
}

class Key_Comp : public leveldb::Comparator
{
public:
    int Compare(const leveldb::Slice &a, const leveldb::Slice &b) const
    {
        uint64 a_u64, b_u64;
        char k1 = a[0];
        char k2 = b[0];

        if(k1 > '9' || k1 < '0')
        {
            if(k2 > '9' || k2 < '0')
            {
                return a.compare(b);
            }

            return -1;
        }

        if(k2 > '9' || k2 < '0')
        {
            return 1;
        }
        
        fly::base::string_to(a.data(), a_u64);
        fly::base::string_to(b.data(), b_u64);
        
        if(a_u64 < b_u64)
        {
            return -1;
        }

        if(a_u64 > b_u64)
        {
            return 1;
        }

        return 0;
    }

    const char* Name() const
    {
        return "Key_Comp";
    }

    void FindShortestSeparator(std::string* start, const leveldb::Slice& limit) const {}
    void FindShortSuccessor(std::string* key) const {}
};

bool Blockchain::hash_pow(char hash_arr[32], uint32 zero_bits)
{
    uint32 zero_char_num = zero_bits / 8;

    for(uint32 i = 0; i < zero_char_num; ++i)
    {
        if(hash_arr[i] != 0)
        {
            return false;
        }
    }
    
    uint32 zero_remain_bit = zero_bits % 8;

    if(zero_remain_bit == 0)
    {
        return true;
    }
    
    return hash_arr[zero_char_num] < 1 << 8 - zero_remain_bit;
}

std::string Blockchain::sign(std::string privk_b64, std::string hash_b64)
{
    char privk[32];
    fly::base::base64_decode(privk_b64.c_str(), privk_b64.size(), privk, 32);
    char hash[32];
    fly::base::base64_decode(hash_b64.c_str(), hash_b64.size(), hash, 32);
    CKey ck;
    ck.Set(privk, privk + 32, false);
    std::vector<unsigned char> sign_vec;

    if(!ck.Sign(uint256(std::vector<unsigned char>(hash, hash + 32)), sign_vec))
    {
        CONSOLE_LOG_FATAL("sign hash: %s failed", hash_b64.c_str());

        return std::string();
    }

    return fly::base::base64_encode(&sign_vec[0], sign_vec.size());
}

bool Blockchain::verify_sign(std::string pubk_b64, std::string hash_b64, std::string sign_b64)
{
    char sign[80];
    uint32 len_sign = fly::base::base64_decode(sign_b64.c_str(), sign_b64.size(), sign, 80);
    char hash[32];
    fly::base::base64_decode(hash_b64.c_str(), hash_b64.size(), hash, 32);
    CPubKey cpk;
    char pubk[65];
    fly::base::base64_decode(pubk_b64.c_str(), pubk_b64.size(), pubk, 65);
    cpk.Set(pubk, pubk + 65);

    return cpk.Verify(uint256(std::vector<unsigned char>(hash, hash + 32)), std::vector<unsigned char>(sign, sign + len_sign));
}

bool Blockchain::get_account(uint64 id, std::shared_ptr<Account> &account)
{
    auto iter = m_account_by_id.find(id);

    if(iter == m_account_by_id.end())
    {
        return false;
    }

    account = iter->second;
}

bool Blockchain::load(std::string db_path)
{
    // firstly, we need verify __asic_resistant_data__
    extern std::vector<uint32> __asic_resistant_data__;
    const uint32 ASIC_RESISTANT_DATA_NUM = 5 * 1024 * 1024;

    if(__asic_resistant_data__.size() != ASIC_RESISTANT_DATA_NUM)
    {
        CONSOLE_LOG_FATAL("verify __asic_resistant_data__ failed, length is not 5 * 1024 * 1024");
        
        return false;
    }
    
    uint32 val_sum = 0, val_mult = 0, val_xor = 0;

    for(uint32 i = 0; i < ASIC_RESISTANT_DATA_NUM; ++i)
    {
        val_sum += __asic_resistant_data__[i];
        val_mult = (val_mult + __asic_resistant_data__[i]) * (val_mult ^ __asic_resistant_data__[i]);
        val_xor ^= __asic_resistant_data__[i];
    }

    if(val_sum != (uint32)278601749 || val_mult != (uint32)3863002825 || val_xor != (uint32)394700363)
    {
        CONSOLE_LOG_FATAL("verify __asic_resistant_data__ failed, invalid data");

        return false;
    }
    
    CONSOLE_LOG_INFO("verify __asic_resistant_data__ ok");

    leveldb::DB *db;
    leveldb::Options options;
    // Key_Comp comp;
    // options.comparator = &comp;
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
        
        std::string genesis_block_data = "{\"data\":{\"id\":0,\"utc\":1518926400,\"version\":10000,\"zero_bits\":0,\"intro\":\"This coin is a gift for those who love freedom.\",\"init_account\":{\"account\":\"lichuan\",\"id\":1,\"avatar\":1,\"pubkey\":\"BH6PNUv9anrjG9GekAd+nus+emyYm1ClCT0gIut1O7A3w6uRl7dAihcD8HvKh+IpOopcgQAzkYxQZ+cxT+32WdM=\"},\"author\":{\"name\":\"Chuan Li\",\"country\":\"China\",\"github\":\"https://github.com/lichuan\",\"mail\":\"308831759@qq.com\",\"belief\":\"In the beginning, God created the heavens and the earth.\"}},\"children\":[]}";

        rapidjson::Document doc;
        doc.Parse(genesis_block_data.c_str());

        if(doc.HasParseError())
        {
            CONSOLE_LOG_FATAL("parse genesis block failed, reason: %s", GetParseError_En(doc.GetParseError()));

            return false;
        }
        
        const rapidjson::Value &data = doc["data"];
        rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
        rapidjson::StringBuffer buffer_1;
        rapidjson::Writer<rapidjson::StringBuffer> writer_1(buffer_1);
        data.Accept(writer_1);
        
        std::string genesis_block_hash = coin_hash_b64(buffer_1.GetString(), buffer_1.GetSize());
        std::string sign_b64 = "MEQCIAtl9A36GVH3/JEKywWnb1qL14o+Hto7qyIt67rGyBbwAiAiZKzMQfPe+juW8sz48P1SFN4Vt0QrYO9qzv+qCY4Uow==";
        
        // sign_b64 = sign("", genesis_block_hash);
        // if(sign_b64.empty())
        // {
        //     return false;
        // }

        doc.AddMember("hash", rapidjson::StringRef(genesis_block_hash.c_str()), allocator);
        doc.AddMember("sign", rapidjson::StringRef(sign_b64.c_str()), allocator);
        
        rapidjson::StringBuffer buffer_2;
        rapidjson::Writer<rapidjson::StringBuffer> writer_2(buffer_2);
        doc.Accept(writer_2);
        s = db->Put(leveldb::WriteOptions(), "0", buffer_2.GetString());

        if(!s.ok())
        {
            return false;
        }

        //try get again
        s = db->Get(leveldb::ReadOptions(), "0", &block_0);

        if(!s.ok())
        {
            return false;
        }
    }
    
    const char *block_0_str = block_0.c_str();
    CONSOLE_LOG_INFO("block0: %s", block_0_str);
    rapidjson::Document doc;
    doc.Parse(block_0_str);
    
    if(doc.HasParseError())
    {
        CONSOLE_LOG_FATAL("parse leveldb block 0 failed, data: %s, reason: %s", block_0_str, GetParseError_En(doc.GetParseError()));

        return false;
    }

    if(!doc.HasMember("hash"))
    {
        return false;
    }

    if(!doc.HasMember("sign"))
    {
        return false;
    }

    if(!doc.HasMember("data"))
    {
        return false;
    }

    std::string block_hash = doc["hash"].GetString();
    std::string block_sign = doc["sign"].GetString();

    if(block_hash != "QKQzeV/UzpDNQDWZGVVU5vyKdTw9MmrTbOD/wfa480Y=")
    {
        return false;
    }

    const rapidjson::Value &data = doc["data"];
    
    if(!data.HasMember("id"))
    {
        return false;
    }

    if(!data.HasMember("utc"))
    {
        return false;
    }

    if(!data.HasMember("version"))
    {
        return false;
    }
    
    if(!data.HasMember("zero_bits"))
    {
        return false;
    }

    if(!data.HasMember("intro"))
    {
        return false;
    }

    if(!data.HasMember("author"))
    {
        return false;
    }
    
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    data.Accept(writer);
    
    //base64 44 bytes length
    if(block_hash.length() != 44)
    {
        CONSOLE_LOG_FATAL("parse leveldb block 0 failed, hash length is not 44 bytes");

        return false;
    }

    std::string block_hash_verify = coin_hash_b64(buffer.GetString(), buffer.GetSize());
    
    if(block_hash != block_hash_verify)
    {
        CONSOLE_LOG_FATAL("verify leveldb block 0 failed, hash doesn't match");
        
        return false;
    }
    
    const rapidjson::Value &init_account = data["init_account"];
    std::string account = init_account["account"].GetString();
    std::string pubkey = init_account["pubkey"].GetString();
    uint64 account_id = init_account["id"].GetUint64();
    uint32 avatar = init_account["avatar"].GetUint();

    if(account != "lichuan" || pubkey != "BH6PNUv9anrjG9GekAd+nus+emyYm1ClCT0gIut1O7A3w6uRl7dAihcD8HvKh+IpOopcgQAzkYxQZ+cxT+32WdM=" \
       || account_id != 1 \
       || avatar != 1)
    {
        return false;
    }
    
    if(!verify_sign(pubkey, block_hash, block_sign))
    {
        CONSOLE_LOG_FATAL("verify genesis block hash sign from leveldb failed");
        
        return false;
    }

    std::string account_b64 = fly::base::base64_encode(account.data(), account.size());
    std::string reserve_fund = "reserve_fund";
    std::string reserve_fund_b64 = fly::base::base64_encode(reserve_fund.data(), reserve_fund.size());
    uint64 reserve_fund_account_id = 0;
    std::shared_ptr<Account> reserve_fund_account(new Account(reserve_fund_account_id, reserve_fund_b64, "", 1));
    uint64 author_account_id = 1;
    std::shared_ptr<Account> author_account(new Account(author_account_id, account_b64, pubkey, 1));
    m_account_names.insert(reserve_fund_b64);
    m_account_names.insert(account_b64);
    uint64 total = 1000000000000000000;
    author_account->set_balance(total / 2);
    reserve_fund_account->set_balance(total / 2);
    m_account_by_id.insert(std::make_pair(0, reserve_fund_account));
    m_account_by_id.insert(std::make_pair(1, author_account));
    uint64 block_id = data["id"].GetUint64();
    uint32 utc = data["utc"].GetUint();
    uint32 version = data["version"].GetUint();
    uint32 zero_bits = data["zero_bits"].GetUint();

    if(block_id != 0)
    {
        return false;
    }

    if(utc != 1518926400)
    {
        return false;
    }

    if(version != 10000)
    {
        return false;
    }

    if(zero_bits != 0)
    {
        return false;
    }
    
    std::shared_ptr<Block> block(new Block(block_id, utc, version, zero_bits, block_hash));
    m_blocks.insert(std::make_pair(block_id, block));
    uint64 prev_block_id = 0;
    std::string prev_block_hash = block_hash;
    uint32 prev_zero_bits = zero_bits;
    uint32 prev_utc = utc;
    uint32 block_utc_diff = 15;
    leveldb::Iterator *it = db->NewIterator(leveldb::ReadOptions());
    CONSOLE_LOG_INFO("start load block from leveldb......");

    for(it->Seek("1"); it->Valid(); it->Next())
    {
        std::string k = it->key().ToString();
        fly::base::string_to(k.c_str(), block_id);
        std::string content = it->value().ToString();
        rapidjson::Document doc;
        doc.Parse(content.c_str());
        
        if(doc.HasParseError())
        {
            CONSOLE_LOG_FATAL("parse leveldb block %lu failed, reason: %s", block_id, GetParseError_En(doc.GetParseError()));
            
            return false;
        }

        if(!doc.HasMember("hash"))
        {
            return false;
        }

        if(!doc.HasMember("sign"))
        {
            return false;
        }

        if(!doc.HasMember("data"))
        {
            return false;
        }
        
        std::string block_hash = doc["hash"].GetString();
        std::string block_sign = doc["sign"].GetString();
        const rapidjson::Value &data = doc["data"];

        if(!data.HasMember("id"))
        {
            return false;
        }

        if(!data.HasMember("utc"))
        {
            return false;
        }
        
        if(!data.HasMember("version"))
        {
            return false;
        }

        uint32 block_version = data["version"].GetUint();

        //here should be changed when new version released.
        if(!version_compatible(block_version, ASKCOIN_VERSION))
        {
            CONSOLE_LOG_FATAL("block %lu version not compatible, block_version: %u, askcoin_version: %u", block_id, block_version, ASKCOIN_VERSION);

            return false;
        }
        
        if(!data.HasMember("zero_bits"))
        {
            return false;
        }

        if(!data.HasMember("prev_hash"))
        {
            return false;
        }

        if(!data.HasMember("miner"))
        {
            return false;
        }

        if(!data.HasMember("tx"))
        {
            return false;
        }

        if(!data.HasMember("nonce1"))
        {
            return false;
        }
        
        if(!data.HasMember("nonce2"))
        {
            return false;
        }
        
        if(!data.HasMember("nonce3"))
        {
            return false;
        }
        
        if(!data.HasMember("nonce4"))
        {
            return false;
        }

        if(!data["nonce1"].IsUint64())
        {
            return false;
        }

        if(!data["nonce2"].IsUint64())
        {
            return false;
        }

        if(!data["nonce3"].IsUint64())
        {
            return false;
        }

        if(!data["nonce4"].IsUint64())
        {
            return false;
        }

        uint64 block_id_from_db = data["id"].GetUint64();
        
        if(block_id_from_db != block_id)
        {
            CONSOLE_LOG_FATAL("leveldb block id doesn't match, block_id: %lu, block_id_from_db: %lu", block_id, block_id_from_db);
            
            return false;
        }

        if(block_id != prev_block_id + 1)
        {
            CONSOLE_LOG_FATAL("leveldb block id doesn't continuously, block_id: %lu, prev_block_id: %lu", block_id, prev_block_id);
            
            return false;
        }
        
        uint32 utc = data["utc"].GetUint();
        uint32 zero_bits = data["zero_bits"].GetUint();

        if(block_utc_diff < 8)
        {
            if(zero_bits != prev_zero_bits + 1)
            {
                return false;
            }
        }
        else if(block_utc_diff > 17)
        {
            if(prev_zero_bits > 1)
            {
                if(zero_bits != prev_zero_bits - 1)
                {
                    return false;
                }
            }
            else
            {
                if(zero_bits != 1)
                {
                    return false;
                }
            }
        }
        else if(zero_bits != prev_zero_bits)
        {
            return false;
        }
        
        if(utc <= prev_utc)
        {
            return false;
        }
        
        uint32 now = time(NULL);
        
        if(utc > now + 2)
        {
            CONSOLE_LOG_FATAL("check leveldb block %lu utc failed, please check your system time", block_id);
            
            return false;
        }
        
        block_utc_diff = utc - prev_utc;
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        data.Accept(writer);
    
        //base64 44 bytes length
        if(block_hash.length() != 44)
        {
            CONSOLE_LOG_FATAL("parse leveldb block %lu failed, hash length is not 44 bytes", block_id);
            
            return false;
        }
        
        std::string block_hash_verify = coin_hash_b64(buffer.GetString(), buffer.GetSize());
    
        if(block_hash != block_hash_verify)
        {
            CONSOLE_LOG_FATAL("verify leveldb block %lu failed, hash doesn't match", block_id);

            return false;
        }

        std::string prev_hash = data["prev_hash"].GetString();

        if(prev_hash != prev_block_hash)
        {
            CONSOLE_LOG_FATAL("verify leveldb block %lu failed, prev_hash doesn't match", block_id);

            return false;
        }

        uint64 miner_id = data["miner"].GetUint64();

        if(miner_id == 0) // reserve_fund_account can't be miner !!!
        {
            return false;
        }
        
        std::shared_ptr<Account> miner;
        
        if(!get_account(miner_id, miner))
        {
            return false;
        }
        
        char block_raw_hash[32];
        uint32 len = fly::base::base64_decode(block_hash.c_str(), block_hash.size(), block_raw_hash, 32);
        
        if(len != 32)
        {
            return false;
        }
        
        if(!hash_pow(block_raw_hash, zero_bits))
        {
            return false;
        }
        
        if(!verify_sign(miner->pubkey(), block_hash, block_sign))
        {
            CONSOLE_LOG_FATAL("verify block %lu hash sign from leveldb failed", block_id);
            
            return false;
        }

        const rapidjson::Value &tx = data["tx"];

        if(!tx.IsArray())
        {
            return false;
        }
        
        prev_block_id = block_id;
        prev_block_hash = block_hash;
        prev_utc = utc;
        prev_zero_bits = zero_bits;
    }
    
    CONSOLE_LOG_INFO("load block from leveldb finished, last block: %lu", block_id);
    m_cur_db_block_id = block_id;
    m_cur_db_block_hash = block_hash;
    
    //s = db->Get(leveldb::ReadOptions(), "bliiock22_count", &val);
    //s = db->Get(leveldb::ReadOptions(), "block_count", &val);
    //s = db->Delete(leveldb::WriteOptions(), "block_couniiwwwwwwwwwwwwt");
        
    // CKey key;
    // key.MakeNewKey(false);
    // CPubKey pubkey = key.GetPubKey();
    // std::string key_b64 = fly::base::base64_encode(key.begin(), key.size());
    // std::string pubkey_b64 = fly::base::base64_encode(pubkey.begin(), pubkey.size());
    // std::string addr = coin_addr(pubkey.begin(), pubkey.size());
    // CONSOLE_LOG_INFO("key: %s, pubkey: %s, addr: %s", key_b64.c_str(), pubkey_b64.c_str(), addr.c_str());

    // std::string k1 = "fHIT5NNDgMCYC4Yyieu+NOGRaxG8MMX9qAzchPPZ8lc";
    // char privk[32];
    // fly::base::base64_decode(k1.c_str(), k1.size(), privk, 32);
    // CKey ck1;
    // ck1.Set(privk, privk + 32, false);
    // CPubKey pubk1 = ck1.GetPubKey();
    // std::string addr1 = coin_addr(pubk1.begin(), pubk1.size());
    // std::string pubk_64 = fly::base::base64_encode(pubk1.begin(), pubk1.size());
    // CONSOLE_LOG_INFO("new pubkey: %s, addr: %s", pubk_64.c_str(), addr1.c_str());


    // std::vector<unsigned char> vec1 = {0x04,0xa5,0xc1,0x77,0xb9,0xe4,0xb5,0xda,0x15,0xc5,0x0e,0x75,0x35,0xbf,0xdd,0xac,0xe5,0x91,0x88,0x32,0xb6,0x87,0x8d,0xac,0xab,0x53,0x51,0xe3,0x5e,0x90,0x17,0xda,0x80,0x6d,0x08,0x87,0x31,0xba,0x78,0x3d,0x04,0x27,0xbb,0x68,0x94,0x01,0x47,0x92,0xe8,0x4e,0x71,0xe2,0xca,0xd0,0x11,0x26,0x01,0x0c,0x4c,0x87,0x97,0xb4,0x2d,0xb8,0x29};
    
    // CPubKey pub(vec1);
    // std::vector<unsigned char> vec2 = {0x30,0x45,0x02,0x20,0x1f,0x02,0x39,0x9a,0xae,0x46,0x2c,0x09,0xd5,0x24,0x84,0x0c,0x88,0xc1,0xd5,0x06,0xea,0x7c,0x6c,0xe8,0x6f,0x71,0x03,0x29,0xbe,0x52,0x12,0xc8,0xc1,0x60,0x0e,0xd9,0x02,0x21,0x00,0x83,0x77,0xe8,0x93,0xd9,0xa4,0x74,0xc6,0x4b,0x37,0xb7,0x70,0xf5,0x85,0xa8,0x37,0xe3,0x3d,0x36,0xa1,0xf6,0xf2,0x73,0xfa,0x92,0xb4,0xd0,0x40,0x1e,0x9d,0xb7,0x26};
    
    // uint256 msg({0x31,0xcd,0xa2,0xab,0x84,0x52,0xa3,0x3d,0x1f,0x25,0x41,0x2e,0x56,0x8c,0x71,0x6d,0x5b,0xb8,0x01,0x45,0xf6,0xad,0xd2,0x6f,0x5f,0x24,0x70,0xf4,0x64,0x22,0xe6,0xf7});
    
    // if(!pub.Verify(msg, vec2)) {
    //     CONSOLE_LOG_ERROR("sign failed............");
    //     return false;
    // }

    // CONSOLE_LOG_INFO("sign success.............");

    // std::string tdata = "a1232323232342342bc";
    // uint160 u160 = Hash160(tdata.begin(), tdata.end());
    // uint256 u256 = Hash(tdata.begin(), tdata.end());
    
    // std::string b64 = EncodeBase64(u160.begin(), u160.size());
    // std::string b642 = fly::base::base64_encode(u160.begin(), u160.size());
    // std::string hex2 = fly::base::byte2hexstr(u160.begin(), u160.size());
    // CONSOLE_LOG_INFO("u160 hex: %02x, %02x", *u160.begin(), *(u160.begin() + 1));
    // std::string hex256_2 = fly::base::byte2hexstr(u256.begin(), u256.size());
    // char buf[CryptoPP::SHA256::DIGESTSIZE] = {0};
    // CONSOLE_LOG_INFO("SHA256::DIGESTSIZE is: %d", CryptoPP::SHA256::DIGESTSIZE);
    
    // if(!fly::base::sha256(tdata.c_str(), tdata.length(), buf, CryptoPP::SHA256::DIGESTSIZE))
    // {
    //     CONSOLE_LOG_FATAL("fly sha256 failed!");
    // }

    // char s256[CSHA256::OUTPUT_SIZE] = {0};
    // CSHA256().Write(tdata.c_str(), tdata.size()).Finalize(s256);
    // std::string s256_hex = fly::base::byte2hexstr(s256, CSHA256::OUTPUT_SIZE);
        
    // std::string hex256_fly = fly::base::byte2hexstr(buf, CryptoPP::SHA256::DIGESTSIZE);
        
    // CONSOLE_LOG_INFO("hex: %s", u160.GetHex().c_str());
    // CONSOLE_LOG_INFO("hex2: %s", hex2.c_str());
    // CONSOLE_LOG_INFO("hex256: %s", u256.GetHex().c_str());
    // CONSOLE_LOG_INFO("hex256_2: %s", hex256_2.c_str());
    // CONSOLE_LOG_INFO("hex256 fly: %s", hex256_fly.c_str());
    // CONSOLE_LOG_INFO("hex256 once: %s", s256_hex.c_str());
    // CONSOLE_LOG_INFO("b64: %s", b64.c_str());
    // CONSOLE_LOG_INFO("b642: %s", b642.c_str());
    // CONSOLE_LOG_INFO("sanity check success.");

    // char arr[10] = {'a','b','c',0x5,'e','f','g','h','a','a'};
    // std::string str = fly::base::byte2hexstr(arr, 10);
    // CONSOLE_LOG_INFO("hexstr: %s", str.c_str());

    // char arr1[11] = {0};
    // uint32 len = fly::base::hexstr2byte(str.c_str(), str.length(), arr1,10);
    // CONSOLE_LOG_INFO("hexstr2byte: len: %d, arr1: %s, %02x", len, arr1, arr1[3]);

    // std::string str1 = fly::base::base64_encode(arr1, 10);
    // std::string str2 = fly::base::base64_encode(arr, 10);
    // CONSOLE_LOG_INFO("str1: %s", str1.c_str());
    // CONSOLE_LOG_INFO("str2: %s", str2.c_str());

    // char arr2[11] = {0};
    // uint32 len2 = fly::base::base64_decode(str1.c_str(), str1.length(), arr2, 10);
    // CONSOLE_LOG_INFO("len2: %d arr2: %s", len2, arr2);
    
    // std::string str_hash = "IJ8NTsepqQTKWi9F2xdY+76H5eiJbElFUrEBNkJu7nw=";
    // std::string str_pub = "BIie7a1Jd5JMzka6rEnm5YusF896bsoE2gUfz4HPqJbPCT8RwT/yIHG2pYtRTfkEzgBRDxIyybqULA5CGDJNivw=";
    // std::string str_sig = "MEYCIQCCDPBA2IMRHyNKvsH00LAH7/7bZBmK36AZeBIzSY05CQIhAOepJCA+RRY08JguV5Hx6Ht3fslDYKAc8UymzEwe1Vd7";
        
    // char arr_hash[40] = {0};
    // char arr_pub[70] = {0};
    // char arr_sig[80] = {0};
    // uint32 len_hash = fly::base::base64_decode(str_hash.c_str(), str_hash.length(), arr_hash, 40);
    // CONSOLE_LOG_INFO("len_hash: %d", len_hash);
    // uint32 len_pub = fly::base::base64_decode(str_pub.c_str(), str_pub.length(), arr_pub, 70);
    // CONSOLE_LOG_INFO("len_pub: %d", len_pub);
    // uint32 len_sig = fly::base::base64_decode(str_sig.c_str(), str_sig.length(), arr_sig, 80);
    // CONSOLE_LOG_INFO("len_sig: %d", len_sig);

    // std::string hex_hash = fly::base::byte2hexstr(arr_hash, 32);
    // std::string hex_sig = fly::base::byte2hexstr(arr_sig, 72);
    // std::string hex_pub = fly::base::byte2hexstr(arr_pub, 65);
    
    // CONSOLE_LOG_INFO("arr_hash: %s", hex_hash.c_str());
    // CONSOLE_LOG_INFO("arr_pub: %s", hex_pub.c_str());
    // CONSOLE_LOG_INFO("arr_sig: %s", hex_sig.c_str());

    // CPubKey pkey;
    // pkey.Set(arr_pub, arr_pub + len_pub);
    
    // if(pkey.Verify(uint256(std::vector<unsigned char>(arr_hash, arr_hash + len_hash)), std::vector<unsigned char>(arr_sig, arr_sig + len_sig)))
    // {
    //     CONSOLE_LOG_INFO("verify ok...............");
    // }
    // else {
    //     CONSOLE_LOG_INFO("verify failed.................");
    // }

    return true;
}
