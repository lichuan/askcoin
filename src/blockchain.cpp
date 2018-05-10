#include <queue>
#include <netinet/in.h>
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
    m_b64_table.fill(0);

    for(char i = 'a'; i <= 'z'; ++i)
    {
        m_b64_table[i] = 64;
    }
    
    for(char i = 'A'; i <= 'Z'; ++i)
    {
        m_b64_table[i] = 64;
    }

    for(char i = '0'; i <= '9'; ++i)
    {
        m_b64_table[i] = 64;
    }
    
    m_b64_table['+'] = 64;
    m_b64_table['/'] = 64;
    m_b64_table['='] = 64;
    m_cur_block_id = 0;
    m_cur_account_id = 0;
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

const uint32 ASIC_RESISTANT_DATA_NUM = 5 * 1024 * 1024;
extern std::vector<uint32> __asic_resistant_data__;

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

bool Blockchain::verify_hash(std::string block_hash, std::string block_data, uint32 zero_bits)
{
    char hash_raw[32];
    uint32 len = fly::base::base64_decode(block_hash.c_str(), block_hash.length(), hash_raw, 32);

    if(len != 32)
    {
        return false;
    }
    
    uint32 buf[16] = {0};
    char *p = (char*)buf;
    coin_hash(block_data.c_str(), block_data.length(), p);
    block_data += "another_32_bytes";
    coin_hash(block_data.c_str(), block_data.length(), p + 32);
    uint32 arr_16[16] = {0};

    for(uint32 i = 0; i < 16; ++i)
    {
        arr_16[i] = ntohl(buf[i]);
    }

    for(uint32 i = 0; i < ASIC_RESISTANT_DATA_NUM;)
    {
        for(int j = 0; j < 16; ++j)
        {
            arr_16[j] = (arr_16[j] + __asic_resistant_data__[i + j]) * (arr_16[j] ^ __asic_resistant_data__[i + j]);
        }
        
        i += 16;
    }
    
    for(uint32 i = 0; i < 16; ++i)
    {
        buf[i] = htonl(arr_16[i]);
    }

    std::string hash_data = block_data + fly::base::base64_encode(p, 64);
    std::string block_hash_verify = coin_hash_b64(hash_data.c_str(), hash_data.length());

    if(block_hash != block_hash_verify)
    {
        return false;
    }
    
    return hash_pow(hash_raw, zero_bits);
}

std::string Blockchain::sign(std::string privk_b64, std::string hash_b64)
{
    char privk[32];
    fly::base::base64_decode(privk_b64.c_str(), privk_b64.length(), privk, 32);
    char hash[32];
    fly::base::base64_decode(hash_b64.c_str(), hash_b64.length(), hash, 32);
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
    uint32 len_sign = fly::base::base64_decode(sign_b64.c_str(), sign_b64.length(), sign, 80);
    char hash[32];
    fly::base::base64_decode(hash_b64.c_str(), hash_b64.length(), hash, 32);
    CPubKey cpk;
    char pubk[65];
    fly::base::base64_decode(pubk_b64.c_str(), pubk_b64.length(), pubk, 65);
    cpk.Set(pubk, pubk + 65);

    return cpk.Verify(uint256(std::vector<unsigned char>(hash, hash + 32)), std::vector<unsigned char>(sign, sign + len_sign));
}

bool Blockchain::is_base64_char(std::string b64)
{
    if(b64.empty())
    {
        return false;
    }

    for(uint32 i = 0; i < b64.length(); ++i)
    {
        unsigned char c = b64[i];
        
        if(m_b64_table[c] != 64)
        {
            return false;
        }
    }

    return true;
}

bool Blockchain::get_account(std::string pubkey, std::shared_ptr<Account> &account)
{
    auto iter = m_account_by_pubkey.find(pubkey);

    if(iter == m_account_by_pubkey.end())
    {
        return false;
    }

    account = iter->second;

    return true;
}

bool Blockchain::account_name_exist(std::string name)
{
    return m_account_names.find(name) != m_account_names.end();
}

bool Blockchain::load(std::string db_path)
{
    // firstly, we need verify __asic_resistant_data__
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
    CONSOLE_LOG_INFO("genesis block: %s", block_0_str);
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

    if(!doc.HasMember("children"))
    {
        return false;
    }
    
    std::string block_hash = doc["hash"].GetString();
    std::string block_sign = doc["sign"].GetString();

    if(block_hash != "QKQzeV/UzpDNQDWZGVVU5vyKdTw9MmrTbOD/wfa480Y=")
    {
        return false;
    }

    if(!is_base64_char(block_sign))
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

    if(!data.HasMember("init_account"))
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
    
    std::string account_b64 = fly::base::base64_encode(account.data(), account.length());
    std::string reserve_fund = "reserve_fund";
    std::string reserve_fund_b64 = fly::base::base64_encode(reserve_fund.data(), reserve_fund.length());
    uint64 reserve_fund_account_id = 0;
    std::shared_ptr<Account> reserve_fund_account(new Account(reserve_fund_account_id, reserve_fund_b64, "", 0));
    uint64 author_account_id = 1;
    m_cur_account_id = 1;
    std::shared_ptr<Account> author_account(new Account(author_account_id, account_b64, pubkey, 0));
    m_account_names.insert(reserve_fund_b64);
    m_account_names.insert(account_b64);
    uint64 total = (uint64)1000000000000000000;
    author_account->set_balance(total / 2);
    reserve_fund_account->set_balance(total / 2);
    m_account_by_pubkey.insert(std::make_pair(pubkey, author_account));
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

    const rapidjson::Value &children = doc["children"];

    if(!children.IsArray())
    {
        return false;
    }

    std::shared_ptr<Block> genesis_block(new Block(block_id, utc, version, zero_bits, block_hash));
    m_blocks.insert(std::make_pair(block_hash, genesis_block));
    std::shared_ptr<Block> the_most_difficult_block = genesis_block;

    struct Child_Block
    {
        std::shared_ptr<Block> m_parent;
        std::string m_hash;
        
        Child_Block(std::shared_ptr<Block> parent, std::string hash)
        {
            m_parent = parent;
            m_hash = hash;
        }
    };

    std::queue<Child_Block> block_queue;
    
    for(rapidjson::Value::ConstValueIterator iter = children.Begin(); iter != children.End(); ++iter)
    {
        Child_Block child_block(genesis_block, iter->GetString());
        block_queue.push(child_block);
    }
    
    while(!block_queue.empty())
    {
        const Child_Block &child_block = block_queue.front();
        std::string block_data;
        s = db->Get(leveldb::ReadOptions(), child_block.m_hash, &block_data);

        if(!s.ok())
        {
            CONSOLE_LOG_FATAL("read block data from leveldb failed, hash: %s", child_block.m_hash.c_str());
            
            return false;
        }
        
        // todo? 1500 tx size?, only txid so not 500?
        const uint32 MAX_BLOCK_SIZE_IN_LEVELDB = 1500 * 44;

        if(block_data.length() > MAX_BLOCK_SIZE_IN_LEVELDB)
        {
            return false;
        }
        
        rapidjson::Document doc;
        const char *block_data_str = block_data.c_str();
        doc.Parse(block_data_str);
        
        if(doc.HasParseError())
        {
            CONSOLE_LOG_FATAL("parse block data from leveldb failed, data: %s, hash: %s, reason: %s", block_data_str, child_block.m_hash.c_str(), \
                              GetParseError_En(doc.GetParseError()));
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

        if(!doc.HasMember("children"))
        {
            return false;
        }
    
        std::string block_hash = doc["hash"].GetString();
        std::string block_sign = doc["sign"].GetString();

        if(!is_base64_char(block_hash))
        {
            return false;
        }

        if(!is_base64_char(block_sign))
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

        if(!data.HasMember("pre_hash"))
        {
            return false;
        }
        
        if(!data.HasMember("miner"))
        {
            return false;
        }

        if(!data.HasMember("tx_ids"))
        {
            return false;
        }

        const rapidjson::Value &tx_ids = data["tx_ids"];

        if(!tx_ids.IsArray())
        {
            return false;
        }
        
        if(!data.HasMember("nonce"))
        {
            return false;
        }
        
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        data.Accept(writer);

        //base64 44 bytes length
        if(block_hash.length() != 44)
        {
            CONSOLE_LOG_FATAL("parse block data from leveldb failed, hash: %s, hash length is not 44 bytes", child_block.m_hash.c_str());
            
            return false;
        }

        std::string data_str(buffer.GetString(), buffer.GetSize());
        std::string block_hash_verify = coin_hash_b64(buffer.GetString(), buffer.GetSize());
        
        if(block_hash != block_hash_verify)
        {
            CONSOLE_LOG_FATAL("verify block data from leveldb failed, hash: %s, hash doesn't match", child_block.m_hash.c_str());

            return false;
        }

        std::string miner_pubkey = data["miner"].GetString();

        if(miner_pubkey.length() != 88)
        {
            return false;
        }

        if(!is_base64_char(miner_pubkey))
        {
            return false;
        }
        
        if(!verify_sign(miner_pubkey, block_hash, block_sign))
        {
            CONSOLE_LOG_FATAL("verify block sign from leveldb failed, hash: %s", child_block.m_hash.c_str());

            return false;
        }

        uint64 block_id = data["id"].GetUint64();
        uint32 utc = data["utc"].GetUint();
        uint32 version = data["version"].GetUint();
        uint32 zero_bits = data["zero_bits"].GetUint();
        std::string pre_hash = data["pre_hash"].GetString();
        const rapidjson::Value &nonce = data["nonce"];

        if(!version_compatible(version, ASKCOIN_VERSION))
        {
            CONSOLE_LOG_FATAL("verify block version from leveldb failed, hash: %s, block version: %u, askcoin version: %u", \
                              child_block.m_hash.c_str(), version, ASKCOIN_VERSION);
            return false;
        }
        
        if(!nonce.IsArray())
        {
            return false;
        }
        
        if(nonce.Size() != 4)
        {
            return false;
        }
        
        for(uint32 i = 0; i < 4; ++i)
        {
            if(!nonce[i].IsUint64())
            {
                return false;
            }
        }
        
        std::shared_ptr<Block> parent = child_block.m_parent;
        uint64 parent_block_id = parent->id();
        uint32 parent_utc = parent->utc();
        std::string parent_hash = parent->hash();
        uint32 parent_zero_bits = parent->zero_bits();
        uint32 utc_diff = parent->utc_diff();
        
        if(block_id != parent_block_id + 1)
        {
            return false;
        }

        if(pre_hash != parent_hash)
        {
            return false;
        }
        
        if(utc_diff < 15)
        {
            if(zero_bits != parent_zero_bits + 1)
            {
                return false;
            }
        }
        else if(utc_diff > 35)
        {
            if(parent_zero_bits > 1)
            {
                if(zero_bits != parent_zero_bits - 1)
                {
                    return false;
                }
            }
            else if(zero_bits != 1)
            {
                return false;
            }
        }
        else if(zero_bits != parent_zero_bits)
        {
            return false;
        }
        
        if(utc <= parent_utc)
        {
            return false;
        }

        uint32 now = time(NULL);
        
        if(utc > now + 2)
        {
            CONSOLE_LOG_FATAL("verify block utc from leveldb failed, hash: %s, please check your system time", child_block.m_hash.c_str(), block_id);
            
            return false;
        }
        
        if(!verify_hash(block_hash, data_str, zero_bits))
        {
            CONSOLE_LOG_FATAL("verify block hash and zero_bits failed, hash: %s", child_block.m_hash.c_str());

            return false;
        }
        
        std::shared_ptr<Block> cur_block(new Block(block_id, utc, version, zero_bits, block_hash));
        cur_block->set_parent(parent);
        parent->add_my_difficulty_to(cur_block);
        
        if(m_blocks.find(block_hash) != m_blocks.end())
        {
            return false;
        }

        m_blocks.insert(std::make_pair(block_hash, cur_block));
        const rapidjson::Value &children = doc["children"];
        
        if(!children.IsArray())
        {
            return false;
        }
        
        for(rapidjson::Value::ConstValueIterator iter = children.Begin(); iter != children.End(); ++iter)
        {
            Child_Block child_block(cur_block, iter->GetString());
            block_queue.push(child_block);
        }

        for(rapidjson::Value::ConstValueIterator iter = tx_ids.Begin(); iter != tx_ids.End(); ++iter)
        {
            cur_block->m_tx_ids.push_back(iter->GetString());
        }
        
        if(cur_block->difficult_than(the_most_difficult_block))
        {
            the_most_difficult_block = cur_block;
        }
        
        block_queue.pop();
    }
    
    std::deque<std::shared_ptr<Block>> block_chain;
    std::shared_ptr<Block> iter_block = the_most_difficult_block;
    m_cur_block_id = the_most_difficult_block->id();
    
    while(iter_block->id() != 0)
    {
        block_chain.push_front(iter_block);
        iter_block = iter_block->get_parent();
    }
    
    // now, load tx in every block in order
    while(!block_chain.empty())
    {
        iter_block = block_chain.front();
        uint64 cur_block_id = iter_block->id();
        const std::vector<std::string> &tx_ids = iter_block->m_tx_ids;
        
        for(auto &tx_id : tx_ids)
        {
            std::string tx_data;
            s = db->Get(leveldb::ReadOptions(), tx_id, &tx_data);

            if(!s.ok())
            {
                CONSOLE_LOG_FATAL("read tx data from leveldb failed, tx_id: %s", tx_id.c_str());
                
                return false;
            }
            
            // todo? max tx size?
            const uint32 MAX_TX_SIZE_IN_LEVELDB = 500;
            
            if(tx_data.length() > MAX_TX_SIZE_IN_LEVELDB)
            {
                return false;
            }

            rapidjson::Document doc;
            const char *tx_data_str = tx_data.c_str();
            doc.Parse(tx_data_str);
        
            if(doc.HasParseError())
            {
                CONSOLE_LOG_FATAL("parse tx data from leveldb failed, data: %s, tx_id: %s, reason: %s", tx_data_str, tx_id.c_str(), \
                                  GetParseError_En(doc.GetParseError()));
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

            std::string tx_sign = doc["sign"].GetString();
            const rapidjson::Value &data = doc["data"];

            if(!is_base64_char(tx_sign))
            {
                return false;
            }
            
            if(!data.HasMember("pubkey"))
            {
                return false;
            }

            if(!data.HasMember("type"))
            {
                return false;
            }
            
            if(!data.HasMember("utc"))
            {
                return false;
            }

            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            data.Accept(writer);
            
            //base64 44 bytes length
            if(tx_id.length() != 44)
            {
                return false;
            }

            std::string data_str(buffer.GetString(), buffer.GetSize());
            std::string tx_id_verify = coin_hash_b64(buffer.GetString(), buffer.GetSize());
        
            if(tx_id != tx_id_verify)
            {
                CONSOLE_LOG_FATAL("verify tx data from leveldb failed, tx_id: %s, hash doesn't match", tx_id.c_str());
                
                return false;
            }

            std::string pubkey = data["pubkey"].GetString();
            
            if(pubkey.length() != 88)
            {
                return false;
            }

            if(!is_base64_char(pubkey))
            {
                return false;
            }
            
            if(!verify_sign(pubkey, tx_id, tx_sign))
            {
                CONSOLE_LOG_FATAL("verify tx sign from leveldb failed, tx_id: %s", tx_id.c_str());
                
                return false;
            }
            
            uint32 tx_type = data["type"].GetUint();
            
            // register account
            if(tx_type == 1)
            {
                std::shared_ptr<Account> account;
                
                if(get_account(pubkey, account))
                {
                    return false;
                }
                
                if(!data.HasMember("avatar"))
                {
                    return false;
                }
                
                if(!data.HasMember("sign"))
                {
                    return false;
                }
                
                if(!data.HasMember("sign_data"))
                {
                    return false;
                }

                std::string reg_sign = data["sign"].GetString();

                if(!is_base64_char(reg_sign))
                {
                    return false;
                }
                
                const rapidjson::Value &sign_data = data["sign_data"];
                rapidjson::StringBuffer buffer;
                rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
                sign_data.Accept(writer);
                std::string sign_hash = coin_hash_b64(buffer.GetString(), buffer.GetSize());
                
                if(!sign_data.HasMember("block_id"))
                {
                    return false;
                }

                if(!sign_data.HasMember("name"))
                {
                    return false;
                }

                if(!sign_data.HasMember("referrer"))
                {
                    return false;
                }

                if(!sign_data.HasMember("fee"))
                {
                    return false;
                }

                uint64 block_id = sign_data["block_id"].GetUint64();
                std::string register_name = sign_data["name"].GetString();
                std::string referrer_pubkey = sign_data["referrer"].GetString();
                uint64 fee = sign_data["fee"].GetUint64();
                
                if(block_id == 0)
                {
                    return false;
                }
                
                if(block_id + 100 < cur_block_id || cur_block_id + 100 < block_id)
                {
                    return false;
                }

                if(fee == 0)
                {
                    return false;
                }

                if(referrer_pubkey.length() != 88)
                {
                    return false;
                }

                if(!is_base64_char(referrer_pubkey))
                {
                    return false;
                }
                
                std::shared_ptr<Account> referrer_account;
                
                if(!get_account(referrer_pubkey, referrer_account))
                {
                    return false;
                }
                
                if(referrer_account->get_balance() < fee)
                {
                    return false;
                }
                
                if(!verify_sign(referrer_pubkey, sign_hash, reg_sign))
                {
                    return false;
                }

                referrer_account->sub_balance(fee);

                if(register_name.length() > 20 || register_name.empty())
                {
                    return false;
                }

                if(!is_base64_char(register_name))
                {
                    return false;
                }

                if(account_name_exist(register_name))
                {
                    return false;
                }
                
                char raw_name[15] = {0};
                uint32 len = fly::base::base64_decode(register_name.c_str(), register_name.length(), raw_name, 15);
                
                if(len > 15 || len == 0)
                {
                    return false;
                }
                
                for(uint32 i = 0; i < len; ++i)
                {
                    if(std::isspace(static_cast<unsigned char>(raw_name[i])))
                    {
                        return false;
                    }
                }
                
                uint32 avatar = data["avatar"].GetUint();
                
                if(avatar >= 8)
                {
                    return false;
                }
                
                std::shared_ptr<Account> reg_account(new Account(++m_cur_account_id, register_name, pubkey, avatar));
                m_account_names.insert(register_name);
                m_account_by_pubkey.insert(std::make_pair(pubkey, reg_account));
            }
            else
            {
                if(!data.HasMember("fee"))
                {
                    return false;
                }

                if(!data.HasMember("block_id"))
                {
                    return false;
                }

                uint64 block_id = data["block_id"].GetUint64();

                if(block_id == 0)
                {
                    return false;
                }

                if(block_id + 100 < cur_block_id || cur_block_id + 100 < block_id)
                {
                    return false;
                }
                
                std::shared_ptr<Account> account;
                
                if(!get_account(pubkey, account))
                {
                    return false;
                }
                
                if(tx_type == 2)
                {
                }
                else if(tx_type == 3)
                {
                }
                else
                {
                    return false;
                }
            }
        }
    }
    
    
    // std::string val;
    // s = db->Get(leveldb::ReadOptions(), "bliiock22_count", &val);
    // if(!s.ok())
    // {
    //     CONSOLE_LOG_INFO("get bliiock22_count error");

    // }
    
    // //s = db->Get(leveldb::ReadOptions(), "block_count", &val);

    
    // s = db->Delete(leveldb::WriteOptions(), "block_couniiwwwwwwwwwwwwt");

    // if(!s.ok())
    // {
    //     CONSOLE_LOG_INFO("delete block_couniiwwwwwwwwwwwwt error");
    //     return false;
    // }

    // CONSOLE_LOG_INFO("delete key not exist success");
    
        
    // CKey key;
    // key.MakeNewKey(false);
    // CPubKey pubkey = key.GetPubKey();
    // std::string key_b64 = fly::base::base64_encode(key.begin(), key.size());
    // std::string pubkey_b64 = fly::base::base64_encode(pubkey.begin(), pubkey.size());
    // std::string addr = coin_addr(pubkey.begin(), pubkey.size());
    // CONSOLE_LOG_INFO("key: %s, pubkey: %s, addr: %s", key_b64.c_str(), pubkey_b64.c_str(), addr.c_str());

    // std::string k1 = "fHIT5NNDgMCYC4Yyieu+NOGRaxG8MMX9qAzchPPZ8lc";
    // char privk[32];
    // fly::base::base64_decode(k1.c_str(), k1.length(), privk, 32);
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
    //     CONSOLE_LOG_FATAL("fly sha256 failed");
    // }

    // char s256[CSHA256::OUTPUT_SIZE] = {0};
    // CSHA256().Write(tdata.c_str(), tdata.length()).Finalize(s256);
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
