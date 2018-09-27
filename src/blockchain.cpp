#include <netinet/in.h>
#include <unistd.h>
#include "leveldb/comparator.h"
#include "fly/base/logger.hpp"
#include "blockchain.hpp"
#include "key.h"
#include "version.hpp"
#include "utilstrencodings.h"
#include "random.h"
#include "cryptopp/sha.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "net/p2p/node.hpp"
#include "net/p2p/message.hpp"

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
    if(sign_b64.length() < 80 || sign_b64.length() > 108)
    {
        return false;
    }
    
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

void Blockchain::del_account_rich(std::shared_ptr<Account> account)
{
    auto iter_end = m_account_by_rich.upper_bound(account);
    
    for(auto iter = m_account_by_rich.lower_bound(account); iter != iter_end; ++iter)
    {
        if(*iter == account)
        {
            m_account_by_rich.erase(iter);
            
            break;
        }
    }
}

void Blockchain::add_account_rich(std::shared_ptr<Account> account)
{
    m_account_by_rich.insert(account);
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

bool Blockchain::get_topic(std::string key, std::shared_ptr<Topic> &topic)
{
    auto iter = m_topics.find(key);

    if(iter == m_topics.end())
    {
        return false;
    }

    topic = iter->second;

    return true;
}

bool Blockchain::proc_tx_map(std::shared_ptr<Block> block)
{
    uint64 cur_block_id = block->id();
    
    if(cur_block_id < (TOPIC_LIFE_TIME + 2))
    {
        return true;
    }

    auto iter = m_rollback_txs.find(cur_block_id - (TOPIC_LIFE_TIME + 1));
    
    if(iter == m_rollback_txs.end())
    {
        std::pair<std::shared_ptr<Block>, std::list<std::string>> value;
        m_rollback_txs.insert(std::make_pair(cur_block_id - (TOPIC_LIFE_TIME + 1), value));
    }
    
    if(cur_block_id > 8641)
    {
        m_rollback_txs.erase(cur_block_id - 8641);
    }
    
    auto &tx_pair = m_rollback_txs[cur_block_id - (TOPIC_LIFE_TIME + 1)];
    std::shared_ptr<Block> iter_block = block;
    uint32 count = 0;
    
    while(iter_block->id() > 1)
    {
        iter_block = iter_block->get_parent();

        if(++count > TOPIC_LIFE_TIME)
        {
            std::string block_data;
            leveldb::Status s = m_db->Get(leveldb::ReadOptions(), iter_block->hash(), &block_data);
            
            if(!s.ok())
            {
                return false;
            }
            
            rapidjson::Document doc;
            const char *block_data_str = block_data.c_str();
            doc.Parse(block_data_str);
        
            if(doc.HasParseError())
            {
                return false;
            }

            if(!doc.IsObject())
            {
                return false;
            }
            
            if(!doc.HasMember("data"))
            {
                return false;
            }

            const rapidjson::Value &data = doc["data"];

            if(!data.HasMember("tx_ids"))
            {
                return false;
            }
        
            const rapidjson::Value &tx_ids = data["tx_ids"];

            if(!tx_ids.IsArray())
            {
                return false;
            }
            
            uint32 tx_num = tx_ids.Size();
            
            if(tx_num > 2000)
            {
                return false;
            }

            tx_pair.first = iter_block;
            
            for(rapidjson::Value::ConstValueIterator iter = tx_ids.Begin(); iter != tx_ids.End(); ++iter)
            {
                std::string tx_id = iter->GetString();
                tx_pair.second.push_front(tx_id);
                
                if(m_tx_map.erase(tx_id) != 1)
                {
                    return false;
                }
            }
            
            break;
        }
    }
    
    return true;
}

bool Blockchain::proc_topic_expired(uint64 cur_block_id)
{
    if(cur_block_id < (TOPIC_LIFE_TIME + 2))
    {
        return true;
    }

    auto iter = m_rollback_topics.find(cur_block_id - (TOPIC_LIFE_TIME + 1));
    
    if(iter == m_rollback_topics.end())
    {
        std::list<std::shared_ptr<Topic>> value;
        m_rollback_topics.insert(std::make_pair(cur_block_id - (TOPIC_LIFE_TIME + 1), value));
    }

    if(cur_block_id > 8641)
    {
        m_rollback_topics.erase(cur_block_id - 8641);
    }

    auto &topic_list = m_rollback_topics[cur_block_id - (TOPIC_LIFE_TIME + 1)];
    
    while(!m_topic_list.empty())
    {
        std::shared_ptr<Topic> topic = m_topic_list.front();

        if(topic->block_id() + TOPIC_LIFE_TIME < cur_block_id)
        {
            m_topics.erase(topic->key());
            topic_list.push_front(topic);
            std::shared_ptr<Account> owner = topic->get_owner();
            
            if(!owner)
            {
                return false;
            }

            if(owner->m_topic_list.empty())
            {
                return false;
            }

            std::shared_ptr<Topic> topic_in_owner = owner->m_topic_list.front();

            if(topic != topic_in_owner)
            {
                return false;
            }

            uint64 balance = topic->get_balance();
            
            if(balance > 0)
            {
                m_reserve_fund_account->add_balance(balance);
            }
            
            owner->m_topic_list.pop_front();
            m_topic_list.pop_front();

            for(auto &p : topic->m_members)
            {
                p.second->leave_topic(topic);
            }
        }
        else
        {
            break;
        }
    }
    
    return true;
}

void Blockchain::do_score()
{
    using namespace net::p2p;
    uint32 wait_tick = 0;

    while(!m_stop.load(std::memory_order_relaxed))
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        if(++wait_tick < 30)
        {
            continue;
        }

        wait_tick = 0;
        auto p2p_node = net::p2p::Node::instance();
        rapidjson::Document doc;
        doc.SetObject();
        rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
        rapidjson::Value peers(rapidjson::kArrayType);
        doc.AddMember("utc", time(NULL), allocator);
        uint32 count = 0;
        std::unique_lock<std::mutex> lock(p2p_node->m_score_mutex);
        auto &peer_scores = p2p_node->m_peer_scores;
        
        while(peer_scores.size() > 5000)
        {
            auto peer_score = *peer_scores.rbegin();
            p2p_node->del_peer_score(peer_score);
        }

        for(auto iter = peer_scores.begin(); iter != peer_scores.end(); ++iter)
        {
            if(++count > 1000)
            {
                break;
            }
            
            std::shared_ptr<Peer_Score> peer_score = *iter;
            rapidjson::Value peer_info(rapidjson::kObjectType);
            peer_info.AddMember("host", rapidjson::StringRef(peer_score->m_addr.m_host.c_str()), allocator);
            peer_info.AddMember("port", peer_score->m_addr.m_port, allocator);
            peer_info.AddMember("score", peer_score->m_score, allocator);
            peers.PushBack(peer_info, allocator);
        }
        
        lock.unlock();
        doc.AddMember("peers", peers, allocator);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        doc.Accept(writer);
        leveldb::Status s = m_db->Put(leveldb::WriteOptions(), "peer_score", buffer.GetString());
        
        if(!s.ok())
        {
            LOG_FATAL("write peer_score failed, reason: %s", s.ToString().c_str());
        }
    }
}

void Blockchain::do_message()
{
    while(!m_stop.load(std::memory_order_relaxed))
    {
        bool peer_empty = false;
        bool wsock_empty = false;
        std::list<std::unique_ptr<fly::net::Message<Json>>> peer_messages;

        if(m_peer_messages.pop(peer_messages))
        {
            for(auto &message : peer_messages)
            {
                do_peer_message(message);
            }
        }
        else
        {
            peer_empty = true;
        }
        
        std::list<std::unique_ptr<fly::net::Message<Wsock>>> wsock_messages;
        
        if(m_wsock_messages.pop(wsock_messages))
        {
            for(auto &message : wsock_messages)
            {
                do_wsock_message(message);
            }
        }
        else
        {
            wsock_empty = true;
        }
        
        bool called = m_timer_ctl.run();
        do_brief_chain();
        
        if(m_block_changed)
        {
            do_uv_tx();
            m_block_changed = false;
        }

        if(peer_empty && wsock_empty && !called)
        {
            RandAddSeedSleep();
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
}

void Blockchain::stop()
{
    m_stop.store(true, std::memory_order_relaxed);
}

void Blockchain::wait()
{
    m_msg_thread.join();
    m_score_thread.join();
}

bool Blockchain::start(std::string db_path)
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

    leveldb::Options options;
    // Key_Comp comp;
    // options.comparator = &comp;
    options.create_if_missing = true;

    // todo, set this param?
    options.max_open_files = 100000;
    options.max_file_size = 50 * (1 << 20);
    leveldb::Status s = leveldb::DB::Open(options, db_path, &m_db);
    
    if(!s.ok())
    {
        CONSOLE_LOG_FATAL("open leveldb failed: %s", s.ToString().c_str());

        return false;
    }

    std::string block_0;
    s = m_db->Get(leveldb::ReadOptions(), "0", &block_0);
    
    if(!s.ok())
    {
        if(!s.IsNotFound())
        {
            CONSOLE_LOG_FATAL("read block_0 from leveldb failed: %s", s.ToString().c_str());

            return false;
        }

        // todo, "this coin" should be changed
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

        LOG_DEBUG_INFO("genesis -------------------data---------------------: %s", buffer_1.GetString());
        std::string genesis_block_hash = coin_hash_b64(buffer_1.GetString(), buffer_1.GetSize());
        std::string sign_b64 = "MEQCIAtl9A36GVH3/JEKywWnb1qL14o+Hto7qyIt67rGyBbwAiAiZKzMQfPe+juW8sz48P1SFN4Vt0QrYO9qzv+qCY4Uow==";
        // sign_b64 = sign("", genesis_block_hash);
        
        doc.AddMember("hash", rapidjson::StringRef(genesis_block_hash.c_str()), allocator);
        doc.AddMember("sign", rapidjson::StringRef(sign_b64.c_str()), allocator);
        
        rapidjson::StringBuffer buffer_2;
        rapidjson::Writer<rapidjson::StringBuffer> writer_2(buffer_2);
        doc.Accept(writer_2);
        s = m_db->Put(leveldb::WriteOptions(), "0", buffer_2.GetString());
        
        if(!s.ok())
        {
            ASKCOIN_RETURN false;
        }

        rapidjson::Document peer_doc;
        peer_doc.SetObject();
        rapidjson::Document::AllocatorType &peer_allocator = peer_doc.GetAllocator();
        rapidjson::Value peers(rapidjson::kArrayType);
        peer_doc.AddMember("utc", time(NULL), peer_allocator);
        peer_doc.AddMember("peers", peers, peer_allocator);
        rapidjson::StringBuffer buffer_3;
        rapidjson::Writer<rapidjson::StringBuffer> writer_3(buffer_3);
        peer_doc.Accept(writer_3);
        s = m_db->Put(leveldb::WriteOptions(), "peer_score", buffer_3.GetString());
        
        if(!s.ok())
        {
            ASKCOIN_RETURN false;
        }
        
        //try get again
        s = m_db->Get(leveldb::ReadOptions(), "0", &block_0);

        if(!s.ok())
        {
            ASKCOIN_RETURN false;
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

    if(!doc.IsObject())
    {
        ASKCOIN_RETURN false;
    }
    
    if(!doc.HasMember("hash"))
    {
        ASKCOIN_RETURN false;
    }

    if(!doc["hash"].IsString())
    {
        ASKCOIN_RETURN false;
    }
    
    if(!doc.HasMember("sign"))
    {
        ASKCOIN_RETURN false;
    }

    if(!doc["sign"].IsString())
    {
        ASKCOIN_RETURN false;
    }
    
    if(!doc.HasMember("data"))
    {
        ASKCOIN_RETURN false;
    }
    
    if(!doc.HasMember("children"))
    {
        ASKCOIN_RETURN false;
    }
    
    std::string block_hash = doc["hash"].GetString();
    std::string block_sign = doc["sign"].GetString();

    if(block_hash != "QKQzeV/UzpDNQDWZGVVU5vyKdTw9MmrTbOD/wfa480Y=")
    {
        ASKCOIN_RETURN false;
    }

    if(!is_base64_char(block_sign))
    {
        ASKCOIN_RETURN false;
    }

    const rapidjson::Value &data = doc["data"];

    if(!data.IsObject())
    {
        ASKCOIN_RETURN false;
    }
    
    if(!data.HasMember("id"))
    {
        ASKCOIN_RETURN false;
    }

    if(!data["id"].IsUint64())
    {
        ASKCOIN_RETURN false;
    }
    
    if(!data.HasMember("utc"))
    {
        ASKCOIN_RETURN false;
    }

    if(!data["utc"].IsUint64())
    {
        ASKCOIN_RETURN false;
    }

    if(!data.HasMember("version"))
    {
        ASKCOIN_RETURN false;
    }

    if(!data["version"].IsUint())
    {
        ASKCOIN_RETURN false;
    }
    
    if(!data.HasMember("zero_bits"))
    {
        ASKCOIN_RETURN false;
    }

    if(!data["zero_bits"].IsUint())
    {
        ASKCOIN_RETURN false;
    }
    
    if(!data.HasMember("intro"))
    {
        ASKCOIN_RETURN false;
    }

    if(!data["intro"].IsString())
    {
        ASKCOIN_RETURN false;
    }
    
    if(!data.HasMember("author"))
    {
        ASKCOIN_RETURN false;
    }

    if(!data["author"].IsObject())
    {
        ASKCOIN_RETURN false;
    }
    
    if(!data.HasMember("init_account"))
    {
        ASKCOIN_RETURN false;
    }

    if(!data["init_account"].IsObject())
    {
        ASKCOIN_RETURN false;
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
        ASKCOIN_RETURN false;
    }
    
    if(!verify_sign(pubkey, block_hash, block_sign))
    {
        CONSOLE_LOG_FATAL("verify genesis block hash sign from leveldb failed");
        
        return false;
    }
    
    std::string account_b64 = fly::base::base64_encode(account.data(), account.length());
    std::string reserve_fund = "reserve_fund";
    std::string reserve_fund_b64 = fly::base::base64_encode(reserve_fund.data(), reserve_fund.length());
    m_reserve_fund_account = std::make_shared<Account>(0, reserve_fund_b64, "", 1);
    std::shared_ptr<Account> author_account(new Account(1, account_b64, pubkey, 1));
    m_cur_account_id = 1;
    m_account_names.insert(reserve_fund_b64);
    m_account_names.insert(account_b64);
    uint64 total = (uint64)1000000000000;
    author_account->set_balance(total / 2);
    m_reserve_fund_account->set_balance(total / 2);
    m_account_by_pubkey.insert(std::make_pair(pubkey, author_account));
    uint64 block_id = data["id"].GetUint64();
    uint64 utc = data["utc"].GetUint64();
    uint32 version = data["version"].GetUint();
    uint32 zero_bits = data["zero_bits"].GetUint();

    if(block_id != 0)
    {
        ASKCOIN_RETURN false;
    }

    if(utc != 1518926400)
    {
        ASKCOIN_RETURN false;
    }

    if(version != 10000)
    {
        ASKCOIN_RETURN false;
    }

    if(zero_bits != 0)
    {
        ASKCOIN_RETURN false;
    }

    const rapidjson::Value &children = doc["children"];

    if(!children.IsArray())
    {
        ASKCOIN_RETURN false;
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

    std::list<Child_Block> block_list;
    
    for(rapidjson::Value::ConstValueIterator iter = children.Begin(); iter != children.End(); ++iter)
    {
        Child_Block child_block(genesis_block, iter->GetString());
        block_list.push_back(child_block);
    }
    
    while(!block_list.empty())
    {
        const Child_Block &child_block = block_list.front();
        std::string block_data;
        s = m_db->Get(leveldb::ReadOptions(), child_block.m_hash, &block_data);

        if(!s.ok())
        {
            CONSOLE_LOG_FATAL("read block data from leveldb failed, hash: %s", child_block.m_hash.c_str());
            
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

        if(!doc.IsObject())
        {
            ASKCOIN_RETURN false;
        }
        
        if(!doc.HasMember("hash"))
        {
            ASKCOIN_RETURN false;
        }

        if(!doc.HasMember("sign"))
        {
            ASKCOIN_RETURN false;
        }

        if(!doc.HasMember("data"))
        {
            ASKCOIN_RETURN false;
        }
        
        if(!doc.HasMember("tx"))
        {
            ASKCOIN_RETURN false;
        }

        const rapidjson::Value &tx = doc["tx"];

        if(!tx.IsArray())
        {
            ASKCOIN_RETURN false;
        }

        if(!doc.HasMember("children"))
        {
            ASKCOIN_RETURN false;
        }
    
        std::string block_hash = doc["hash"].GetString();
        std::string block_sign = doc["sign"].GetString();
        
        if(!is_base64_char(block_hash))
        {
            ASKCOIN_RETURN false;
        }

        if(block_hash.length() != 44)
        {
            ASKCOIN_RETURN false;
        }

        if(block_hash != child_block.m_hash)
        {
            ASKCOIN_RETURN false;
        }
        
        if(!is_base64_char(block_sign))
        {
            ASKCOIN_RETURN false;
        }
        
        const rapidjson::Value &data = doc["data"];
    
        if(!data.HasMember("id"))
        {
            ASKCOIN_RETURN false;
        }

        if(!data.HasMember("utc"))
        {
            ASKCOIN_RETURN false;
        }

        if(!data.HasMember("version"))
        {
            ASKCOIN_RETURN false;
        }
    
        if(!data.HasMember("zero_bits"))
        {
            ASKCOIN_RETURN false;
        }

        if(!data.HasMember("pre_hash"))
        {
            ASKCOIN_RETURN false;
        }
        
        if(!data.HasMember("miner"))
        {
            ASKCOIN_RETURN false;
        }

        if(!data.HasMember("tx_ids"))
        {
            ASKCOIN_RETURN false;
        }

        const rapidjson::Value &tx_ids = data["tx_ids"];

        if(!tx_ids.IsArray())
        {
            ASKCOIN_RETURN false;
        }

        uint32 tx_num = tx_ids.Size();

        if(tx_num > 2000)
        {
            ASKCOIN_RETURN false;
        }
        
        if(tx.Size() != tx_num)
        {
            ASKCOIN_RETURN false;
        }
        
        // todo
        if(block_data.length() > 500 + tx_num * 44)
        {
            ASKCOIN_RETURN false;
        }
        
        if(!data.HasMember("nonce"))
        {
            ASKCOIN_RETURN false;
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

        if(!is_base64_char(miner_pubkey))
        {
            ASKCOIN_RETURN false;
        }

        if(miner_pubkey.length() != 88)
        {
            ASKCOIN_RETURN false;
        }

        std::shared_ptr<Account> miner_account;
                
        if(!get_account(miner_pubkey, miner_account))
        {
            ASKCOIN_RETURN false;
        }
        
        if(!verify_sign(miner_pubkey, block_hash, block_sign))
        {
            CONSOLE_LOG_FATAL("verify block sign from leveldb failed, hash: %s", child_block.m_hash.c_str());

            return false;
        }
        
        uint64 block_id = data["id"].GetUint64();
        uint64 utc = data["utc"].GetUint64();
        uint32 version = data["version"].GetUint();
        uint32 zero_bits = data["zero_bits"].GetUint();
        std::string pre_hash = data["pre_hash"].GetString();
        const rapidjson::Value &nonce = data["nonce"];

        // todo, merge and pruning? version compatible?
        if(!version_compatible(version, ASKCOIN_VERSION))
        {
            CONSOLE_LOG_FATAL("verify block version from leveldb failed, hash: %s, block version: %u, askcoin version: %u", \
                              child_block.m_hash.c_str(), version, ASKCOIN_VERSION);
            return false;
        }
        
        if(!nonce.IsArray())
        {
            ASKCOIN_RETURN false;
        }
        
        if(nonce.Size() != 4)
        {
            ASKCOIN_RETURN false;
        }
        
        for(uint32 i = 0; i < 4; ++i)
        {
            if(!nonce[i].IsUint64())
            {
                ASKCOIN_RETURN false;
            }
        }
        
        std::shared_ptr<Block> parent = child_block.m_parent;
        uint64 parent_block_id = parent->id();
        uint64 parent_utc = parent->utc();
        std::string parent_hash = parent->hash();
        uint32 parent_zero_bits = parent->zero_bits();
        uint64 utc_diff = parent->utc_diff();
        
        if(block_id != parent_block_id + 1)
        {
            ASKCOIN_RETURN false;
        }

        if(pre_hash != parent_hash)
        {
            ASKCOIN_RETURN false;
        }
        
        if(utc_diff < 15)
        {
            if(zero_bits != parent_zero_bits + 1)
            {
                ASKCOIN_RETURN false;
            }
        }
        else if(utc_diff > 35)
        {
            if(parent_zero_bits > 1)
            {
                if(zero_bits != parent_zero_bits - 1)
                {
                    ASKCOIN_RETURN false;
                }
            }
            else if(zero_bits != 1)
            {
                ASKCOIN_RETURN false;
            }
        }
        else if(zero_bits != parent_zero_bits)
        {
            ASKCOIN_RETURN false;
        }
        
        if(utc < parent_utc)
        {
            ASKCOIN_RETURN false;
        }

        uint64 now = time(NULL);
        
        if(utc > now)
        {
            CONSOLE_LOG_FATAL("verify block utc from leveldb failed, id: %lu, hash: %s, please check your system time", block_id, child_block.m_hash.c_str());

            return false;
        }
        
        if(!verify_hash(block_hash, data_str, zero_bits))
        {
            CONSOLE_LOG_FATAL("verify block hash and zero_bits failed, hash: %s", child_block.m_hash.c_str());

            return false;
        }
        
        std::shared_ptr<Block> cur_block(new Block(block_id, utc, version, zero_bits, block_hash));
        cur_block->set_parent(parent);
        cur_block->set_miner(miner_account);
        parent->add_my_difficulty_to(cur_block);
        
        if(m_blocks.find(block_hash) != m_blocks.end())
        {
            ASKCOIN_RETURN false;
        }
        
        m_blocks.insert(std::make_pair(block_hash, cur_block));
        const rapidjson::Value &children = doc["children"];
        
        if(!children.IsArray())
        {
            ASKCOIN_RETURN false;
        }
        
        for(rapidjson::Value::ConstValueIterator iter = children.Begin(); iter != children.End(); ++iter)
        {
            Child_Block child_block(cur_block, iter->GetString());
            block_list.push_back(child_block);
        }

        if(cur_block->difficult_than(the_most_difficult_block))
        {
            the_most_difficult_block = cur_block;
        }
        
        block_list.pop_front();
    }
    
    std::list<std::shared_ptr<Block>> block_chain;
    std::shared_ptr<Block> iter_block = the_most_difficult_block;
    m_cur_block = the_most_difficult_block;
    m_most_difficult_block = the_most_difficult_block;

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
        std::string block_data;
        s = m_db->Get(leveldb::ReadOptions(), iter_block->hash(), &block_data);
        
        if(!s.ok())
        {
            ASKCOIN_RETURN false;
        }
        
        rapidjson::Document doc;
        const char *block_data_str = block_data.c_str();
        doc.Parse(block_data_str);
        
        if(doc.HasParseError())
        {
            ASKCOIN_RETURN false;
        }

        if(!doc.IsObject())
        {
            ASKCOIN_RETURN false;
        }
        
        if(!doc.HasMember("data"))
        {
            ASKCOIN_RETURN false;
        }

        if(!doc.HasMember("tx"))
        {
            ASKCOIN_RETURN false;
        }

        const rapidjson::Value &data = doc["data"];
        
        if(!data.IsObject())
        {
            ASKCOIN_RETURN false;
        }
        
        if(!data.HasMember("tx_ids"))
        {
            ASKCOIN_RETURN false;
        }
        
        const rapidjson::Value &tx_ids = data["tx_ids"];
        const rapidjson::Value &tx = doc["tx"];
        
        if(!tx_ids.IsArray())
        {
            ASKCOIN_RETURN false;
        }

        if(!tx.IsArray())
        {
            ASKCOIN_RETURN false;
        }
        
        uint32 tx_num = tx_ids.Size();

        if(tx_num > 2000)
        {
            ASKCOIN_RETURN false;
        }
        
        if(tx.Size() != tx_num)
        {
            ASKCOIN_RETURN false;
        }
        
        std::shared_ptr<Account> miner = iter_block->get_miner();

        if(!miner)
        {
            ASKCOIN_RETURN false;
        }

        if(!proc_topic_expired(cur_block_id))
        {
            ASKCOIN_RETURN false;
        }

        if(!proc_tx_map(iter_block))
        {
            ASKCOIN_RETURN false;
        }
        
        for(uint32 i = 0; i < tx_num; ++i)
        {
            std::string tx_id = tx_ids[i].GetString();
            
            // tx can not be replayed.
            if(m_tx_map.find(tx_id) != m_tx_map.end())
            {
                ASKCOIN_RETURN false;
            }
            
            const rapidjson::Value &tx_node = tx[i];

            if(!tx_node.IsObject())
            {
                ASKCOIN_RETURN false;
            }
            
            if(!tx_node.HasMember("sign"))
            {
                ASKCOIN_RETURN false;
            }

            if(!tx_node.HasMember("data"))
            {
                ASKCOIN_RETURN false;
            }
            
            std::string tx_sign = tx_node["sign"].GetString();
            const rapidjson::Value &data = tx_node["data"];

            if(!is_base64_char(tx_sign))
            {
                ASKCOIN_RETURN false;
            }
            
            if(!data.HasMember("pubkey"))
            {
                ASKCOIN_RETURN false;
            }

            if(!data.HasMember("type"))
            {
                ASKCOIN_RETURN false;
            }
            
            if(!data.HasMember("utc"))
            {
                ASKCOIN_RETURN false;
            }
            
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            data.Accept(writer);
            
            //base64 44 bytes length
            if(tx_id.length() != 44)
            {
                ASKCOIN_RETURN false;
            }

            std::string tx_id_verify = coin_hash_b64(buffer.GetString(), buffer.GetSize());
            
            if(tx_id != tx_id_verify)
            {
                CONSOLE_LOG_FATAL("verify tx data from leveldb failed, tx_id: %s, hash doesn't match", tx_id.c_str());
                
                ASKCOIN_RETURN false;
            }
            
            std::string pubkey = data["pubkey"].GetString();

            if(!is_base64_char(pubkey))
            {
                ASKCOIN_RETURN false;
            }

            if(pubkey.length() != 88)
            {
                ASKCOIN_RETURN false;
            }

            if(!verify_sign(pubkey, tx_id, tx_sign))
            {
                CONSOLE_LOG_FATAL("verify tx sign from leveldb failed, tx_id: %s", tx_id.c_str());
                
                return false;
            }
            
            uint32 tx_type = data["type"].GetUint();

            if(tx_type == 1) // register account
            {
                if(!data.HasMember("avatar"))
                {
                    ASKCOIN_RETURN false;
                }
                
                if(!data.HasMember("sign"))
                {
                    ASKCOIN_RETURN false;
                }
                
                std::shared_ptr<Account> exist_account;
                
                if(get_account(pubkey, exist_account))
                {
                    ASKCOIN_RETURN false;
                }
                
                if(!data.HasMember("sign_data"))
                {
                    ASKCOIN_RETURN false;
                }

                std::string reg_sign = data["sign"].GetString();

                if(!is_base64_char(reg_sign))
                {
                    ASKCOIN_RETURN false;
                }
                
                const rapidjson::Value &sign_data = data["sign_data"];

                if(!sign_data.IsObject())
                {
                    ASKCOIN_RETURN false;
                }

                rapidjson::StringBuffer buffer;
                rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
                sign_data.Accept(writer);
                std::string sign_hash = coin_hash_b64(buffer.GetString(), buffer.GetSize());
                
                if(!sign_data.HasMember("block_id"))
                {
                    ASKCOIN_RETURN false;
                }

                if(!sign_data.HasMember("name"))
                {
                    ASKCOIN_RETURN false;
                }

                if(!sign_data.HasMember("referrer"))
                {
                    ASKCOIN_RETURN false;
                }
                
                if(!sign_data.HasMember("fee"))
                {
                    ASKCOIN_RETURN false;
                }
                
                uint64 block_id = sign_data["block_id"].GetUint64();
                std::string register_name = sign_data["name"].GetString();
                std::string referrer_pubkey = sign_data["referrer"].GetString();
                uint64 fee = sign_data["fee"].GetUint64();
                
                if(block_id == 0)
                {
                    ASKCOIN_RETURN false;
                }

                // todo, edge case
                if(block_id + 100 < cur_block_id || block_id > cur_block_id + 100)
                {
                    ASKCOIN_RETURN false;
                }
                
                if(fee != 2)
                {
                    ASKCOIN_RETURN false;
                }
                
                if(!is_base64_char(referrer_pubkey))
                {
                    ASKCOIN_RETURN false;
                }

                if(referrer_pubkey.length() != 88)
                {
                    ASKCOIN_RETURN false;
                }
                
                std::shared_ptr<Account> referrer;
                
                if(!get_account(referrer_pubkey, referrer))
                {
                    ASKCOIN_RETURN false;
                }
                
                if(referrer->get_balance() < 2)
                {
                    ASKCOIN_RETURN false;
                }
                
                if(!verify_sign(referrer_pubkey, sign_hash, reg_sign))
                {
                    ASKCOIN_RETURN false;
                }

                std::shared_ptr<Account> referrer_referrer = referrer->get_referrer();
                referrer->sub_balance(2);
                miner->add_balance(1);

                if(!referrer_referrer)
                {
                    if(referrer->id() > 1)
                    {
                        ASKCOIN_RETURN false;
                    }

                    m_reserve_fund_account->add_balance(1);
                }
                else
                {
                    referrer_referrer->add_balance(1);
                }
                
                if(!is_base64_char(register_name))
                {
                    ASKCOIN_RETURN false;
                }

                if(register_name.length() > 20 || register_name.length() < 4)
                {
                    ASKCOIN_RETURN false;
                }
                
                if(account_name_exist(register_name))
                {
                    ASKCOIN_RETURN false;
                }

                char raw_name[15] = {0};
                uint32 len = fly::base::base64_decode(register_name.c_str(), register_name.length(), raw_name, 15);
                
                if(len > 15 || len == 0)
                {
                    ASKCOIN_RETURN false;
                }
                
                for(uint32 i = 0; i < len; ++i)
                {
                    if(std::isspace(static_cast<unsigned char>(raw_name[i])))
                    {
                        ASKCOIN_RETURN false;
                    }
                }
                
                uint32 avatar = data["avatar"].GetUint();
                
                if(avatar < 1 || avatar > 100)
                {
                    ASKCOIN_RETURN false;
                }
                
                std::shared_ptr<Account> reg_account(new Account(++m_cur_account_id, register_name, pubkey, avatar));
                m_account_names.insert(register_name);
                m_account_by_pubkey.insert(std::make_pair(pubkey, reg_account));
                reg_account->set_referrer(referrer);
            }
            else
            {
                if(!data.HasMember("fee"))
                {
                    ASKCOIN_RETURN false;
                }
                
                if(!data.HasMember("block_id"))
                {
                    ASKCOIN_RETURN false;
                }

                uint64 fee = data["fee"].GetUint64();
                uint64 block_id = data["block_id"].GetUint64();
                
                if(block_id == 0)
                {
                    ASKCOIN_RETURN false;
                }

                // todo, edge case
                if(block_id + 100 < cur_block_id || block_id > cur_block_id + 100)
                {
                    ASKCOIN_RETURN false;
                }
                
                if(fee != 2)
                {
                    ASKCOIN_RETURN false;
                }

                std::shared_ptr<Account> account;
                
                if(!get_account(pubkey, account))
                {
                    ASKCOIN_RETURN false;
                }

                if(account->get_balance() < 2)
                {
                    ASKCOIN_RETURN false;
                }
                
                std::shared_ptr<Account> referrer = account->get_referrer();
                account->sub_balance(2);
                miner->add_balance(1);
                
                if(!referrer)
                {
                    if(account->id() > 1)
                    {
                        ASKCOIN_RETURN false;
                    }

                    m_reserve_fund_account->add_balance(1);
                }
                else
                {
                    referrer->add_balance(1);
                }
                
                if(tx_type == 2) // send coin
                {
                    std::string memo = data["memo"].GetString();

                    if(!memo.empty())
                    {
                        if(!is_base64_char(memo))
                        {
                            ASKCOIN_RETURN false;
                        }

                        if(memo.length() > 80 || memo.length() < 4)
                        {
                            ASKCOIN_RETURN false;
                        }
                    }
                    
                    uint64 amount = data["amount"].GetUint64();
                    
                    if(amount == 0)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    if(account->get_balance() < amount)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    std::string receiver_pubkey = data["receiver"].GetString();
                    
                    if(!is_base64_char(receiver_pubkey))
                    {
                        ASKCOIN_RETURN false;
                    }

                    if(receiver_pubkey.length() != 88)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    std::shared_ptr<Account> receiver;
                    
                    if(!get_account(receiver_pubkey, receiver))
                    {
                        ASKCOIN_RETURN false;
                    }

                    account->sub_balance(amount);
                    receiver->add_balance(amount);
                }
                else if(tx_type == 3) // new topic
                {
                    if(!data.HasMember("reward"))
                    {
                        ASKCOIN_RETURN false;
                    }

                    uint64 reward = data["reward"].GetUint64();

                    if(reward == 0)
                    {
                        ASKCOIN_RETURN false;
                    }

                    if(account->get_balance() < reward)
                    {
                        ASKCOIN_RETURN false;
                    }

                    std::shared_ptr<Topic> exist_topic;

                    if(get_topic(tx_id, exist_topic))
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    std::string topic_data = data["topic"].GetString();
                    
                    if(!is_base64_char(topic_data))
                    {
                        ASKCOIN_RETURN false;
                    }

                    if(topic_data.length() < 4 || topic_data.length() > 400)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    if(account->m_topic_list.size() >= 100)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    account->sub_balance(reward);
                    std::shared_ptr<Topic> topic(new Topic(tx_id, topic_data, cur_block_id, reward));
                    topic->set_owner(account);
                    account->m_topic_list.push_back(topic);
                    m_topic_list.push_back(topic);
                    m_topics.insert(std::make_pair(tx_id, topic));
                }
                else if(tx_type == 4) // reply
                {
                    std::string topic_key = data["topic_key"].GetString();
                    
                    if(!is_base64_char(topic_key))
                    {
                        ASKCOIN_RETURN false;
                    }

                    if(topic_key.length() != 44)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    std::shared_ptr<Topic> topic;
                    
                    if(!get_topic(topic_key, topic))
                    {
                        ASKCOIN_RETURN false;
                    }

                    std::string reply_data = data["reply"].GetString();
                    
                    if(!is_base64_char(reply_data))
                    {
                        ASKCOIN_RETURN false;
                    }

                    if(reply_data.length() < 4 || reply_data.length() > 400)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    std::shared_ptr<Reply> reply(new Reply(tx_id, 0, reply_data));
                    reply->set_owner(account);
                    
                    if(topic->m_reply_list.size() >= 1000)
                    {
                        ASKCOIN_RETURN false;
                    }

                    topic->m_reply_list.push_back(reply);
                    
                    if(data.HasMember("reply_to"))
                    {
                        std::string reply_to_key = data["reply_to"].GetString();

                        if(!is_base64_char(reply_to_key))
                        {
                            ASKCOIN_RETURN false;
                        }

                        if(reply_to_key.length() != 44)
                        {
                            ASKCOIN_RETURN false;
                        }
                        
                        std::shared_ptr<Reply> reply_to;
                        
                        if(!topic->get_reply(reply_to_key, reply_to))
                        {
                            ASKCOIN_RETURN false;
                        }

                        if(reply_to->type() != 0)
                        {
                            ASKCOIN_RETURN false;
                        }
                        
                        reply->set_reply_to(reply_to);
                    }

                    if(topic->get_owner() != account)
                    {
                        if(!account->joined_topic(topic))
                        {
                            if(account->m_joined_topic_list.size() >= 100)
                            {
                                ASKCOIN_RETURN false;
                            }

                            account->m_joined_topic_list.push_back(topic);
                            topic->add_member(tx_id, account);
                        }
                    }
                }
                else if(tx_type == 5) // reward
                {
                    std::string topic_key = data["topic_key"].GetString();
                    
                    if(!is_base64_char(topic_key))
                    {
                        ASKCOIN_RETURN false;
                    }

                    if(topic_key.length() != 44)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    std::shared_ptr<Topic> topic;
                    
                    if(!get_topic(topic_key, topic))
                    {
                        ASKCOIN_RETURN false;
                    }

                    if(topic->get_owner() != account)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    std::shared_ptr<Reply> reply(new Reply(tx_id, 1, ""));
                    reply->set_owner(account);
                    
                    if(topic->m_reply_list.size() >= 1000)
                    {
                        ASKCOIN_RETURN false;
                    }

                    uint64 amount = data["amount"].GetUint64();
                    
                    if(amount == 0)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    if(topic->get_balance() < amount)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    std::string reply_to_key = data["reply_to"].GetString();
                    
                    if(!is_base64_char(reply_to_key))
                    {
                        ASKCOIN_RETURN false;
                    }

                    if(reply_to_key.length() != 44)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    std::shared_ptr<Reply> reply_to;
                        
                    if(!topic->get_reply(reply_to_key, reply_to))
                    {
                        ASKCOIN_RETURN false;
                    }

                    if(reply_to->type() != 0)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    reply->set_reply_to(reply_to);
                    topic->sub_balance(amount);
                    reply_to->add_balance(amount);
                    reply_to->get_owner()->add_balance(amount);
                    reply->add_balance(amount);
                    topic->m_reply_list.push_back(reply);
                }
                else
                {
                    ASKCOIN_RETURN false;
                }
            }
            
            m_tx_map.insert(std::make_pair(tx_id, iter_block));
        }

        uint64 remain_balance = m_reserve_fund_account->get_balance();

        if(remain_balance >= 5000)
        {
            m_reserve_fund_account->sub_balance(5000);
            miner->add_balance(5000);
            iter_block->m_miner_reward = true;
        }
        else
        {
            iter_block->m_miner_reward = false;
        }
        
        block_chain.pop_front();

        if(block_chain.empty())
        {
            m_broadcast_json.m_hash = doc["hash"];
            m_broadcast_json.m_sign = doc["sign"];
            m_broadcast_json.m_data = doc["data"];
        }
    }
    
    CONSOLE_LOG_INFO("load block finished, cur_block_id: %lu, cur_block_hash: %s", m_cur_block->id(), m_cur_block->hash().c_str());
    m_timer_ctl.add_timer([=]() {
            broadcast();
        }, 10);
    
    if(!check_balance())
    {
        CONSOLE_LOG_FATAL("check_balance failed");

        ASKCOIN_RETURN false;
    }
    
    {
        std::string peer_data;
        s = m_db->Get(leveldb::ReadOptions(), "peer_score", &peer_data);
        
        if(!s.ok())
        {
            CONSOLE_LOG_FATAL("read peer score data from leveldb failed: %s", s.ToString().c_str());

            return false;
        }
        
        rapidjson::Document doc;
        const char *peer_data_str = peer_data.c_str();
        CONSOLE_LOG_INFO("peer score data from leveldb: %s", peer_data_str);
        doc.Parse(peer_data_str);
        
        if(doc.HasParseError())
        {
            ASKCOIN_RETURN false;
        }

        if(!doc.IsObject())
        {
            ASKCOIN_RETURN false;
        }
        
        if(!doc.HasMember("peers"))
        {
            ASKCOIN_RETURN false;
        }

        if(!doc.HasMember("utc"))
        {
            ASKCOIN_RETURN false;
        }

        if(!doc["utc"].IsUint64())
        {
            ASKCOIN_RETURN false;
        }
        
        const rapidjson::Value &peers = doc["peers"];

        if(!peers.IsArray())
        {
            ASKCOIN_RETURN false;
        }
    
        for(rapidjson::Value::ConstValueIterator iter = peers.Begin(); iter != peers.End(); ++iter)
        {
            const rapidjson::Value &peer_info = *iter;

            if(!peer_info.HasMember("host"))
            {
                ASKCOIN_RETURN false;
            }

            if(!peer_info.HasMember("port"))
            {
                ASKCOIN_RETURN false;
            }

            if(!peer_info.HasMember("score"))
            {
                ASKCOIN_RETURN false;
            }
            
            std::shared_ptr<net::p2p::Peer_Score> peer_score(new net::p2p::Peer_Score(fly::net::Addr(peer_info["host"].GetString(), peer_info["port"].GetUint()), peer_info["score"].GetUint64()));
            net::p2p::Node::instance()->add_peer_score(peer_score);
        }
    }
    
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

    std::thread msg_thread(std::bind(&Blockchain::do_message, this));
    m_msg_thread = std::move(msg_thread);

    std::thread score_thread(std::bind(&Blockchain::do_score, this));
    m_score_thread = std::move(score_thread);
    
    return true;
}

bool Blockchain::check_balance()
{
    // todo, make sure the total coin is equal to 1000000000000
    return true;
}

void Blockchain::do_uv_tx()
{
    uint64 cur_block_id  = m_cur_block->id();

    for(auto iter = m_uv_1_txs.begin(); iter != m_uv_1_txs.end();)
    {
        auto tx = *iter;
        auto tx_type = tx->m_type;
        auto block_id = tx->m_block_id;
        auto tx_id = tx->m_id;
        auto pubkey = tx->m_pubkey;

        if(tx_type == 1)
        {
            std::shared_ptr<tx::Tx_Reg> tx_reg = std::static_pointer_cast<tx::Tx_Reg>(tx);
            auto register_name = tx_reg->m_register_name;
            std::shared_ptr<Account> exist_account;

            if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 100)
            {
                iter = m_uv_1_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                m_uv_account_names.erase(register_name);
                m_uv_account_pubkeys.erase(pubkey);
                continue;
            }
        
            if(m_tx_map.find(tx_id) != m_tx_map.end())
            {
                iter = m_uv_1_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                m_uv_account_names.erase(register_name);
                m_uv_account_pubkeys.erase(pubkey);
                continue;
            }
            
            if(get_account(pubkey, exist_account))
            {
                iter = m_uv_1_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                m_uv_account_names.erase(register_name);
                m_uv_account_pubkeys.erase(pubkey);
                continue;
            }
            
            if(account_name_exist(register_name))
            {
                iter = m_uv_1_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                m_uv_account_names.erase(register_name);
                m_uv_account_pubkeys.erase(pubkey);
                continue;
            }
            
            std::shared_ptr<Account> referrer;
            
            if(!get_account(tx_reg->m_referrer_pubkey, referrer))
            {
                ++iter;
                continue;
            }
            
            if(referrer->get_balance() < 2 + referrer->m_uv_spend)
            {
                ++iter;
                continue;
            }

            referrer->m_uv_spend += 2;
        }
        else
        {
            if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 100)
            {
                iter = m_uv_1_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                continue;
            }
        
            if(m_tx_map.find(tx_id) != m_tx_map.end())
            {
                iter = m_uv_1_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                continue;
            }
            
            if(tx_type == 2)
            {
                std::shared_ptr<tx::Tx_Send> tx_send = std::static_pointer_cast<tx::Tx_Send>(tx);
                std::shared_ptr<Account> account;
            
                if(!get_account(pubkey, account))
                {
                    ++iter;
                    continue;
                }
            
                if(account->get_balance() < tx_send->m_amount + 2 + account->m_uv_spend)
                {
                    ++iter;
                    continue;
                }
            
                std::shared_ptr<Account> receiver;
            
                if(!get_account(tx_send->m_receiver_pubkey, receiver))
                {
                    ++iter;
                    continue;
                }

                account->m_uv_spend += tx_send->m_amount + 2;
            }
            else if(tx_type == 3)
            {
                std::shared_ptr<tx::Tx_Topic> tx_topic = std::static_pointer_cast<tx::Tx_Topic>(tx);
                uint64 reward = tx_topic->m_reward;
                std::shared_ptr<Topic> exist_topic;
                
                if(get_topic(tx_id, exist_topic))
                {
                    iter = m_uv_1_txs.erase(iter);
                    m_uv_tx_ids.erase(tx_id);
                    continue;
                }

                std::shared_ptr<Account> account;
                
                if(!get_account(pubkey, account))
                {
                    ++iter;
                    continue;
                }
                
                if(account->m_topic_list.size() + account->m_uv_topic >= 100)
                {
                    iter = m_uv_1_txs.erase(iter);
                    m_uv_tx_ids.erase(tx_id);
                    continue;
                }
                
                if(account->get_balance() < reward + 2 + account->m_uv_spend)
                {
                    ++iter;
                    continue;
                }

                account->m_uv_spend += reward + 2;
                account->m_uv_topic += 1;
            }
            else if(tx_type == 4)
            {
                std::shared_ptr<tx::Tx_Reply> tx_reply = std::static_pointer_cast<tx::Tx_Reply>(tx);
                std::shared_ptr<Topic> topic;

                if(!get_topic(tx_reply->m_topic_key, topic))
                {
                    ++iter;
                    continue;
                }

                if(topic->block_id() + TOPIC_LIFE_TIME < cur_block_id + 1)
                {
                    iter = m_uv_1_txs.erase(iter);
                    m_uv_tx_ids.erase(tx_id);
                    continue;
                }

                if(!tx_reply->m_reply_to.empty())
                {
                    std::shared_ptr<Reply> reply_to;
                    
                    if(!topic->get_reply(tx_reply->m_reply_to, reply_to))
                    {
                        ++iter;
                        continue;
                    }

                    if(reply_to->type() != 0)
                    {
                        punish_peer(tx_reply->m_peer);
                        iter = m_uv_1_txs.erase(iter);
                        m_uv_tx_ids.erase(tx_id);
                        continue;
                    }
                }
                
                if(topic->m_reply_list.size() + topic->m_uv_reply >= 1000)
                {
                    iter = m_uv_1_txs.erase(iter);
                    m_uv_tx_ids.erase(tx_id);
                    continue;
                }
                
                std::shared_ptr<Account> account;
                
                if(!get_account(pubkey, account))
                {
                    ++iter;
                    continue;
                }
                
                if(account->get_balance() < 2 + account->m_uv_spend)
                {
                    ++iter;
                    continue;
                }
                
                if(topic->get_owner() != account)
                {
                    if(!account->joined_topic(topic))
                    {
                        if(account->m_joined_topic_list.size() + account->m_uv_join_topic >= 100)
                        {
                            iter = m_uv_1_txs.erase(iter);
                            m_uv_tx_ids.erase(tx_id);
                            continue;
                        }
                        
                        account->m_uv_join_topic += 1;
                        tx_reply->m_uv_join_topic = 1;
                    }
                }
                
                account->m_uv_spend += 2;
                topic->m_uv_reply += 1;
            }
            else if(tx_type == 5)
            {
                std::shared_ptr<tx::Tx_Reward> tx_reward = std::static_pointer_cast<tx::Tx_Reward>(tx);
                std::shared_ptr<Account> account;
                
                if(!get_account(pubkey, account))
                {
                    ++iter;
                    continue;
                }
                
                if(account->get_balance() < 2 + account->m_uv_spend + tx_reward->m_amount)
                {
                    ++iter;
                    continue;
                }
                
                std::shared_ptr<Topic> topic;
                    
                if(!get_topic(tx_reward->m_topic_key, topic))
                {
                    ++iter;
                    continue;
                }

                if(topic->block_id() + TOPIC_LIFE_TIME < cur_block_id + 1)
                {
                    iter = m_uv_1_txs.erase(iter);
                    m_uv_tx_ids.erase(tx_id);
                    continue;
                }
                
                if(topic->get_owner() != account)
                {
                    punish_peer(tx_reward->m_peer);
                    iter = m_uv_1_txs.erase(iter);
                    m_uv_tx_ids.erase(tx_id);
                    continue;
                }
                
                if(topic->m_reply_list.size() + topic->m_uv_reply >= 1000)
                {
                    iter = m_uv_1_txs.erase(iter);
                    m_uv_tx_ids.erase(tx_id);
                    continue;
                }
                
                if(topic->get_balance() < tx_reward->m_amount + topic->m_uv_reward)
                {
                    iter = m_uv_1_txs.erase(iter);
                    m_uv_tx_ids.erase(tx_id);
                    continue;
                }
                
                std::shared_ptr<Reply> reply_to;
                    
                if(!topic->get_reply(tx_reward->m_reply_to, reply_to))
                {
                    ++iter;
                    continue;
                }
                
                if(reply_to->type() != 0)
                {
                    punish_peer(tx_reward->m_peer);
                    iter = m_uv_1_txs.erase(iter);
                    m_uv_tx_ids.erase(tx_id);
                    continue;
                }
                
                account->m_uv_spend += 2;
                topic->m_uv_reward += tx_reward->m_amount;
                topic->m_uv_reply += 1;
            }
        }
        
        iter = m_uv_1_txs.erase(iter);
        m_uv_2_txs.push_back(tx);
        net::p2p::Node::instance()->broadcast(*tx->m_doc);
    }
    
    for(auto iter = m_uv_2_txs.begin(); iter != m_uv_2_txs.end();)
    {
        auto tx = *iter;
        auto tx_type = tx->m_type;
        auto block_id = tx->m_block_id;
        auto tx_id = tx->m_id;
        auto pubkey = tx->m_pubkey;

        if(tx_type == 1)
        {
            std::shared_ptr<tx::Tx_Reg> tx_reg = std::static_pointer_cast<tx::Tx_Reg>(tx);
            auto register_name = tx_reg->m_register_name;
            fly::base::Scope_CB scb(
                [this, tx_reg] {
                    std::shared_ptr<Account> referrer;
                    
                    if(!get_account(tx_reg->m_referrer_pubkey, referrer))
                    {
                        return;
                    }
                    
                    if(referrer->m_uv_spend >= 2)
                    {
                        referrer->m_uv_spend -= 2;
                    }
                    else
                    {
                        referrer->m_uv_spend = 0;
                    }
                },[] {});
            
            if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 100)
            {
                iter = m_uv_2_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                m_uv_account_names.erase(register_name);
                m_uv_account_pubkeys.erase(pubkey);
                continue;
            }

            if(m_tx_map.find(tx_id) != m_tx_map.end())
            {
                iter = m_uv_2_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                m_uv_account_names.erase(register_name);
                m_uv_account_pubkeys.erase(pubkey);
                m_uv_3_txs.insert(tx);
                continue;
            }
            
            std::shared_ptr<Account> exist_account;

            if(get_account(pubkey, exist_account))
            {
                iter = m_uv_2_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                m_uv_account_names.erase(register_name);
                m_uv_account_pubkeys.erase(pubkey);
                continue;
            }
            
            if(account_name_exist(register_name))
            {
                iter = m_uv_2_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                m_uv_account_names.erase(register_name);
                m_uv_account_pubkeys.erase(pubkey);
                continue;
            }

            scb.set_cur_cb(1);
        }
        else if(tx_type == 2)
        {
            std::shared_ptr<tx::Tx_Send> tx_send = std::static_pointer_cast<tx::Tx_Send>(tx);
            fly::base::Scope_CB scb(
                [this, tx_send, &pubkey] {
                    std::shared_ptr<Account> account;
                    
                    if(!get_account(pubkey, account))
                    {
                        return;
                    }
                    
                    if(account->m_uv_spend >= tx_send->m_amount + 2)
                    {
                        account->m_uv_spend -= tx_send->m_amount + 2;
                    }
                    else
                    {
                        account->m_uv_spend = 0;
                    }
                },[] {});
            
            if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 100)
            {
                iter = m_uv_2_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                continue;
            }
            
            if(m_tx_map.find(tx_id) != m_tx_map.end())
            {
                iter = m_uv_2_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                m_uv_3_txs.insert(tx);
                continue;
            }

            scb.set_cur_cb(1);
        }
        else if(tx_type == 3)
        {
            std::shared_ptr<tx::Tx_Topic> tx_topic = std::static_pointer_cast<tx::Tx_Topic>(tx);
            uint64 reward = tx_topic->m_reward;
            fly::base::Scope_CB scb(
                [this, reward, &pubkey] {
                    std::shared_ptr<Account> account;
            
                    if(!get_account(pubkey, account))
                    {
                        return;
                    }
                    
                    if(account->m_uv_spend >= reward + 2)
                    {
                        account->m_uv_spend -= reward + 2;
                    }
                    else
                    {
                        account->m_uv_spend = 0;
                    }
                    
                    if(account->m_uv_topic >= 1)
                    {
                        account->m_uv_topic -= 1;
                    }
                },[] {});

            if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 100)
            {
                iter = m_uv_2_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                continue;
            }

            if(m_tx_map.find(tx_id) != m_tx_map.end())
            {
                iter = m_uv_2_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                m_uv_3_txs.insert(tx);
                continue;
            }

            scb.set_cur_cb(1);
        }
        else if(tx_type == 4)
        {
            std::shared_ptr<tx::Tx_Reply> tx_reply = std::static_pointer_cast<tx::Tx_Reply>(tx);
            std::shared_ptr<Topic> topic_outer;
            std::shared_ptr<Account> account_outer;
            
            if(get_topic(tx_reply->m_topic_key, topic_outer))
            {
                if(topic_outer->block_id() + TOPIC_LIFE_TIME < cur_block_id + 1)
                {
                    iter = m_uv_2_txs.erase(iter);
                    m_uv_tx_ids.erase(tx_id);

                    if(topic_outer->m_uv_reply >= 1)
                    {
                        topic_outer->m_uv_reply -= 1;
                    }
                    
                    if(get_account(pubkey, account_outer))
                    {
                        if(account_outer->m_uv_spend >= 2)
                        {
                            account_outer->m_uv_spend -= 2;
                        }
                        else
                        {
                            account_outer->m_uv_spend = 0;
                        }

                        if(tx_reply->m_uv_join_topic > 0)
                        {
                            if(account_outer->m_uv_join_topic >= 1)
                            {
                                account_outer->m_uv_join_topic -= 1;
                            }
                        }
                    }
                    
                    continue;
                }
            }
            
            fly::base::Scope_CB scb(
                [this, tx_reply, &pubkey] {
                    std::shared_ptr<Topic> topic;
                    std::shared_ptr<Account> account;

                    if(!get_account(pubkey, account))
                    {
                        if(get_topic(tx_reply->m_topic_key, topic))
                        {
                            if(topic->m_uv_reply >= 1)
                            {
                                topic->m_uv_reply -= 1;
                            }
                        }
                    }
                    else if(!get_topic(tx_reply->m_topic_key, topic))
                    {
                        if(account->m_uv_spend >= 2)
                        {
                            account->m_uv_spend -= 2;
                        }
                        else
                        {
                            account->m_uv_spend = 0;
                        }
                        
                        if(tx_reply->m_uv_join_topic > 0)
                        {
                            if(account->m_uv_join_topic >= 1)
                            {
                                account->m_uv_join_topic -= 1;
                            }
                        }
                    }
                    else
                    {
                        if(account->m_uv_spend >= 2)
                        {
                            account->m_uv_spend -= 2;
                        }
                        else
                        {
                            account->m_uv_spend = 0;
                        }
                
                        if(tx_reply->m_uv_join_topic > 0)
                        {
                            if(account->m_uv_join_topic >= 1)
                            {
                                account->m_uv_join_topic -= 1;
                            }
                        }
                        
                        if(topic->m_uv_reply >= 1)
                        {
                            topic->m_uv_reply -= 1;
                        }
                    }
                },[] {});
            
            if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 100)
            {
                iter = m_uv_2_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                continue;
            }
            
            if(m_tx_map.find(tx_id) != m_tx_map.end())
            {
                iter = m_uv_2_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                m_uv_3_txs.insert(tx);
                continue;
            }
            
            scb.set_cur_cb(1);
        }
        else if(tx_type == 5)
        {
            std::shared_ptr<tx::Tx_Reward> tx_reward = std::static_pointer_cast<tx::Tx_Reward>(tx);
            std::shared_ptr<Topic> topic_outer;
            std::shared_ptr<Account> account_outer;
            
            if(get_topic(tx_reward->m_topic_key, topic_outer))
            {
                if(topic_outer->block_id() + TOPIC_LIFE_TIME < cur_block_id + 1)
                {
                    iter = m_uv_2_txs.erase(iter);
                    m_uv_tx_ids.erase(tx_id);
                    
                    if(topic_outer->m_uv_reply >= 1)
                    {
                        topic_outer->m_uv_reply -= 1;
                    }

                    if(topic_outer->m_uv_reward >= tx_reward->m_amount)
                    {
                        topic_outer->m_uv_reward -= tx_reward->m_amount;
                    }
                    else
                    {
                        topic_outer->m_uv_reward = 0;
                    }
                    
                    if(get_account(pubkey, account_outer))
                    {
                        if(account_outer->m_uv_spend >= 2)
                        {
                            account_outer->m_uv_spend -= 2;
                        }
                        else
                        {
                            account_outer->m_uv_spend = 0;
                        }
                    }
                    
                    continue;
                }
            }
            
            fly::base::Scope_CB scb(
                [this, tx_reward, &pubkey] {
                    std::shared_ptr<Account> account;
                    std::shared_ptr<Topic> topic;
                    
                    if(!get_account(pubkey, account))
                    {
                        if(get_topic(tx_reward->m_topic_key, topic))
                        {
                            if(topic->m_uv_reply >= 1)
                            {
                                topic->m_uv_reply -= 1;
                            }

                            if(topic->m_uv_reward >= tx_reward->m_amount)
                            {
                                topic->m_uv_reward -= tx_reward->m_amount;
                            }
                            else
                            {
                                topic->m_uv_reward = 0;
                            }
                        }
                    }
                    else if(!get_topic(tx_reward->m_topic_key, topic))
                    {
                        if(account->m_uv_spend >= 2)
                        {
                            account->m_uv_spend -= 2;
                        }
                        else
                        {
                            account->m_uv_spend = 0;
                        }
                    }
                    else
                    {
                        if(account->m_uv_spend >= 2)
                        {
                            account->m_uv_spend -= 2;
                        }
                        else
                        {
                            account->m_uv_spend = 0;
                        }

                        if(topic->m_uv_reply >= 1)
                        {
                            topic->m_uv_reply -= 1;
                        }
                        
                        if(topic->m_uv_reward >= tx_reward->m_amount)
                        {
                            topic->m_uv_reward -= tx_reward->m_amount;
                        }
                        else
                        {
                            topic->m_uv_reward = 0;
                        }
                    }
                },[] {});
            
            if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 100)
            {
                iter = m_uv_2_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                continue;
            }
            
            if(m_tx_map.find(tx_id) != m_tx_map.end())
            {
                iter = m_uv_2_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                m_uv_3_txs.insert(tx);
                continue;
            }

            scb.set_cur_cb(1);
        }
        
        if(tx->m_broadcast_num++ < 5)
        {
            net::p2p::Node::instance()->broadcast(*tx->m_doc);
        }
        
        ++iter;
    }

    for(auto iter = m_uv_2_txs.begin(); iter != m_uv_2_txs.end();)
    {
        // todo mining?
    }

    for(auto iter = m_uv_3_txs.begin(); iter != m_uv_3_txs.end();)
    {
        auto tx = *iter;
        auto block_id = tx->m_block_id;
        auto tx_id = tx->m_id;

        if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 100)
        {
            iter = m_uv_3_txs.erase(iter);
            continue;
        }
        
        if(m_tx_map.find(tx_id) != m_tx_map.end())
        {
            tx->m_broadcast_num = 0;
        }
        else if(tx->m_broadcast_num++ < 5)
        {
            net::p2p::Node::instance()->broadcast(*tx->m_doc);
        }
        
        ++iter;
    }
}

void Blockchain::dispatch_peer_message(std::unique_ptr<fly::net::Message<Json>> message)
{
    m_peer_messages.push(std::move(message));
}

void Blockchain::dispatch_wsock_message(std::unique_ptr<fly::net::Message<Wsock>> message)
{
    m_wsock_messages.push(std::move(message));
}

void Blockchain::switch_chain(std::shared_ptr<Pending_Chain> pending_chain)
{
    m_is_switching = true;
    std::shared_ptr<Block> iter_block = m_cur_block;
    std::shared_ptr<Block> iter_block_1;
    std::shared_ptr<Pending_Block> first_pending_block = pending_chain->m_req_blocks.front();
    std::shared_ptr<Pending_Block> last_pending_block = pending_chain->m_req_blocks.back();
    uint64 pending_block_num = pending_chain->m_req_blocks.size();
    uint64 id = iter_block->id();
    uint64 id_pending = first_pending_block->m_id;
    uint64 cross_id = 0;
    std::string cross_hash;
    std::string iter_hash = first_pending_block->m_hash;
    LOG_INFO("switch chain, cur_block(id: %u, hash: %s) first_pending_block(id: %u, hash: %s, pre_hash: %s) last_pending_block(id: %u, hash: %s) from peer: %s", \
             id, iter_block->hash().c_str(), first_pending_block->m_id, first_pending_block->m_hash.c_str(), first_pending_block->m_pre_hash.c_str(), \
             last_pending_block->m_id, last_pending_block->m_hash.c_str(), pending_chain->m_peer->key().c_str());
    std::list<std::shared_ptr<Block>> db_blocks;
    
    if(id == id_pending)
    {
        while(true)
        {
            if(iter_block->hash() == iter_hash)
            {
                cross_id = iter_block->id();
                cross_hash = iter_block->hash();
                
                if(!db_blocks.empty())
                {
                    db_blocks.pop_front();
                }

                break;
            }
            
            if(!iter_block_1)
            {
                iter_block_1 = m_blocks[first_pending_block->m_pre_hash];
            }
            else
            {
                iter_block_1 = iter_block_1->get_parent();
            }
            
            iter_block = iter_block->get_parent();
            iter_hash = iter_block_1->hash();
            db_blocks.push_front(iter_block_1);
        }
    }
    else if(id < id_pending)
    {
        while(id < id_pending)
        {
            if(!iter_block_1)
            {
                iter_block_1 = m_blocks[first_pending_block->m_pre_hash];
            }
            else
            {
                iter_block_1 = iter_block_1->get_parent();
            }
            
            id_pending = iter_block_1->id();
            iter_hash = iter_block_1->hash();
            db_blocks.push_front(iter_block_1);
        }
        
        while(true)
        {
            if(iter_block->hash() == iter_hash)
            {
                cross_id = iter_block->id();
                cross_hash = iter_block->hash();
                db_blocks.pop_front();

                break;
            }
            
            iter_block_1 = iter_block_1->get_parent();
            iter_block = iter_block->get_parent();
            iter_hash = iter_block_1->hash();
            db_blocks.push_front(iter_block_1);
        }
    }
    else
    {
        uint64 id_pending_last = last_pending_block->m_id;
        
        while(id > id_pending_last)
        {
            iter_block = iter_block->get_parent();
            id  = iter_block->id();
        }
        
        uint64 diff = id_pending_last - id;
        uint64 idx = pending_block_num - 1 - diff;
        iter_hash = pending_chain->m_req_blocks[idx]->m_hash;
        
        while(true)
        {
            if(iter_block->hash() == iter_hash)
            {
                cross_id = iter_block->id();
                cross_hash = iter_hash;
                
                if(!db_blocks.empty())
                {
                    db_blocks.pop_front();
                }
                
                break;
            }
            
            iter_block = iter_block->get_parent();
            
            if(idx > 0)
            {
                --idx;
                iter_hash = pending_chain->m_req_blocks[idx]->m_hash;
            }
            else
            {
                if(!iter_block_1)
                {
                    iter_block_1 = m_blocks[first_pending_block->m_pre_hash];
                }
                else
                {
                    iter_block_1 = iter_block_1->get_parent();
                }
                    
                iter_hash = iter_block_1->hash();
                db_blocks.push_front(iter_block_1);
            }
        }
    }

    if(cross_id == 0)
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    uint64 cur_id  = m_cur_block->id();
    
    if(cross_id < cur_id)
    {
        uint64 distance = cur_id - cross_id;
        LOG_INFO("switch chain, rollback distance: %lu, from peer: %s", distance, pending_chain->m_peer->key().c_str());
        
        if(distance > 50)
        {
            LOG_WARN("switch chain, rollback distance too long, distance: %lu, from peer: %s", distance, pending_chain->m_peer->key().c_str());
        }
        
        rollback(cross_id);
        m_block_changed = true;
    }
    
    if(cross_id >= first_pending_block->m_id)
    {
        pending_chain->m_start = cross_id + 1 - first_pending_block->m_id;
    }

    for(auto i = pending_chain->m_start; i < pending_block_num; ++i)
    {
        auto iter = m_blocks.find(pending_chain->m_req_blocks[i]->m_hash);

        if(iter == m_blocks.end())
        {
            pending_chain->m_start = i;

            break;
        }

        db_blocks.push_back(iter->second);
    }
    
    for(auto iter_block : db_blocks)
    {
        m_cur_block = iter_block;
        uint64 cur_block_id = iter_block->id();
        
        if(cur_block_id == 0)
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
        
        std::string block_data;
        std::string block_hash = iter_block->hash();
        leveldb::Status s = m_db->Get(leveldb::ReadOptions(), block_hash, &block_data);
        
        if(!s.ok())
        {
            LOG_FATAL("switch chain, leveldb read failed, block_id: %lu, block_hash: %s, reason: %s", \
                      cur_block_id, block_hash.c_str(), s.ToString().c_str());
            
            ASKCOIN_EXIT(EXIT_FAILURE);
        }

        rapidjson::Document doc;
        const char *block_data_str = block_data.c_str();
        doc.Parse(block_data_str);
        
        if(doc.HasParseError())
        {
            LOG_FATAL("swich chain, parse block data failed, block_id: %lu, block_hash: %s, reason: %s", \
                      cur_block_id, block_hash.c_str(), GetParseError_En(doc.GetParseError()));

            ASKCOIN_EXIT(EXIT_FAILURE);
        }

        if(!doc.IsObject())
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
        
        if(!doc.HasMember("data"))
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }

        if(!doc.HasMember("tx"))
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }

        const rapidjson::Value &data = doc["data"];

        if(!data.HasMember("tx_ids"))
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
        
        const rapidjson::Value &tx_ids = data["tx_ids"];
        const rapidjson::Value &tx = doc["tx"];
        
        if(!tx_ids.IsArray())
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }

        if(!tx.IsArray())
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
        
        uint32 tx_num = tx_ids.Size();

        if(tx_num > 2000)
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
        
        if(tx.Size() != tx_num)
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
        
        std::shared_ptr<Account> miner = iter_block->get_miner();

        if(!miner)
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }

        if(!proc_topic_expired(cur_block_id))
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }

        if(!proc_tx_map(iter_block))
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
        
        for(uint32 i = 0; i < tx_num; ++i)
        {
            std::string tx_id = tx_ids[i].GetString();

            if(m_tx_map.find(tx_id) != m_tx_map.end())
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
            
            const rapidjson::Value &tx_node = tx[i];

            if(!tx_node.IsObject())
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
            
            if(!tx_node.HasMember("sign"))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }

            if(!tx_node.HasMember("data"))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
            
            std::string tx_sign = tx_node["sign"].GetString();
            const rapidjson::Value &data = tx_node["data"];

            if(!is_base64_char(tx_sign))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
            
            if(!data.HasMember("pubkey"))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }

            if(!data.HasMember("type"))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
            
            if(!data.HasMember("utc"))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
            
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            data.Accept(writer);
            
            //base64 44 bytes length
            if(tx_id.length() != 44)
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }

            std::string tx_id_verify = coin_hash_b64(buffer.GetString(), buffer.GetSize());
            
            if(tx_id != tx_id_verify)
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
            
            std::string pubkey = data["pubkey"].GetString();
            
            if(!is_base64_char(pubkey))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }

            if(pubkey.length() != 88)
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
            
            if(!verify_sign(pubkey, tx_id, tx_sign))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
            
            uint32 tx_type = data["type"].GetUint();

            if(tx_type == 1) // register account
            {
                if(!data.HasMember("avatar"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                if(!data.HasMember("sign"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                std::shared_ptr<Account> exist_account;
                
                if(get_account(pubkey, exist_account))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                if(!data.HasMember("sign_data"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                std::string reg_sign = data["sign"].GetString();

                if(!is_base64_char(reg_sign))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                const rapidjson::Value &sign_data = data["sign_data"];
                rapidjson::StringBuffer buffer;
                rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
                sign_data.Accept(writer);
                std::string sign_hash = coin_hash_b64(buffer.GetString(), buffer.GetSize());
                
                if(!sign_data.HasMember("block_id"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(!sign_data.HasMember("name"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(!sign_data.HasMember("referrer"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                if(!sign_data.HasMember("fee"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                uint64 block_id = sign_data["block_id"].GetUint64();
                std::string register_name = sign_data["name"].GetString();
                std::string referrer_pubkey = sign_data["referrer"].GetString();
                uint64 fee = sign_data["fee"].GetUint64();
                
                if(block_id == 0)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(block_id + 100 < cur_block_id || block_id > cur_block_id + 100)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                if(fee != 2)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                if(!is_base64_char(referrer_pubkey))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                if(referrer_pubkey.length() != 88)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                std::shared_ptr<Account> referrer;
                
                if(!get_account(referrer_pubkey, referrer))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                if(referrer->get_balance() < 2)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                if(!verify_sign(referrer_pubkey, sign_hash, reg_sign))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                std::shared_ptr<Account> referrer_referrer = referrer->get_referrer();
                referrer->sub_balance(2);
                miner->add_balance(1);

                if(!referrer_referrer)
                {
                    if(referrer->id() > 1)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    m_reserve_fund_account->add_balance(1);
                }
                else
                {
                    referrer_referrer->add_balance(1);
                }
                
                if(!is_base64_char(register_name))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(register_name.length() > 20 || register_name.length() < 4)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                if(account_name_exist(register_name))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                char raw_name[15] = {0};
                uint32 len = fly::base::base64_decode(register_name.c_str(), register_name.length(), raw_name, 15);
                
                if(len > 15 || len == 0)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                for(uint32 i = 0; i < len; ++i)
                {
                    if(std::isspace(static_cast<unsigned char>(raw_name[i])))
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                }
                
                uint32 avatar = data["avatar"].GetUint();

                if(avatar < 1 || avatar > 100)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                std::shared_ptr<Account> reg_account(new Account(++m_cur_account_id, register_name, pubkey, avatar));
                m_account_names.insert(register_name);
                m_account_by_pubkey.insert(std::make_pair(pubkey, reg_account));
                reg_account->set_referrer(referrer);
            }
            else
            {
                if(!data.HasMember("fee"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                if(!data.HasMember("block_id"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                uint64 fee = data["fee"].GetUint64();
                uint64 block_id = data["block_id"].GetUint64();
                
                if(block_id == 0)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(block_id + 100 < cur_block_id || block_id > cur_block_id + 100)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                if(fee != 2)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                std::shared_ptr<Account> account;
                
                if(!get_account(pubkey, account))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(account->get_balance() < 2)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                std::shared_ptr<Account> referrer = account->get_referrer();
                account->sub_balance(2);
                miner->add_balance(1);
                
                if(!referrer)
                {
                    if(account->id() > 1)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    m_reserve_fund_account->add_balance(1);
                }
                else
                {
                    referrer->add_balance(1);
                }
                
                if(tx_type == 2) // send coin
                {
                    std::string memo = data["memo"].GetString();

                    if(!memo.empty())
                    {
                        if(!is_base64_char(memo))
                        {
                            ASKCOIN_EXIT(EXIT_FAILURE);
                        }

                        if(memo.length() > 80 || memo.length() < 4)
                        {
                            ASKCOIN_EXIT(EXIT_FAILURE);
                        }
                    }
                    
                    uint64 amount = data["amount"].GetUint64();
                    
                    if(amount == 0)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    if(account->get_balance() < amount)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    std::string receiver_pubkey = data["receiver"].GetString();
                    
                    if(!is_base64_char(receiver_pubkey))
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    if(receiver_pubkey.length() != 88)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    std::shared_ptr<Account> receiver;
                    
                    if(!get_account(receiver_pubkey, receiver))
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    account->sub_balance(amount);
                    receiver->add_balance(amount);
                }
                else if(tx_type == 3) // new topic
                {
                    if(!data.HasMember("reward"))
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    uint64 reward = data["reward"].GetUint64();

                    if(reward == 0)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    if(account->get_balance() < reward)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    std::shared_ptr<Topic> exist_topic;

                    if(get_topic(tx_id, exist_topic))
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    std::string topic_data = data["topic"].GetString();
                    
                    if(!is_base64_char(topic_data))
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    if(topic_data.length() < 4 || topic_data.length() > 400)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    if(account->m_topic_list.size() >= 100)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    account->sub_balance(reward);
                    std::shared_ptr<Topic> topic(new Topic(tx_id, topic_data, cur_block_id, reward));
                    topic->set_owner(account);
                    account->m_topic_list.push_back(topic);
                    m_topic_list.push_back(topic);
                    m_topics.insert(std::make_pair(tx_id, topic));
                }
                else if(tx_type == 4) // reply
                {
                    std::string topic_key = data["topic_key"].GetString();
                    
                    if(!is_base64_char(topic_key))
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    if(topic_key.length() != 44)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    std::shared_ptr<Topic> topic;
                    
                    if(!get_topic(topic_key, topic))
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    std::string reply_data = data["reply"].GetString();
                    
                    if(!is_base64_char(reply_data))
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    if(reply_data.length() < 4 || reply_data.length() > 400)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    std::shared_ptr<Reply> reply(new Reply(tx_id, 0, reply_data));
                    reply->set_owner(account);
                    
                    if(topic->m_reply_list.size() >= 1000)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    topic->m_reply_list.push_back(reply);
                    
                    if(data.HasMember("reply_to"))
                    {
                        std::string reply_to_key = data["reply_to"].GetString();

                        if(!is_base64_char(reply_to_key))
                        {
                            ASKCOIN_EXIT(EXIT_FAILURE);
                        }

                        if(reply_to_key.length() != 44)
                        {
                            ASKCOIN_EXIT(EXIT_FAILURE);
                        }
                        
                        std::shared_ptr<Reply> reply_to;
                        
                        if(!topic->get_reply(reply_to_key, reply_to))
                        {
                            ASKCOIN_EXIT(EXIT_FAILURE);
                        }
                        
                        if(reply_to->type() != 0)
                        {
                            ASKCOIN_EXIT(EXIT_FAILURE);
                        }
                        
                        reply->set_reply_to(reply_to);
                    }

                    if(topic->get_owner() != account)
                    {
                        if(!account->joined_topic(topic))
                        {
                            if(account->m_joined_topic_list.size() >= 100)
                            {
                                ASKCOIN_EXIT(EXIT_FAILURE);
                            }

                            account->m_joined_topic_list.push_back(topic);
                            topic->add_member(tx_id, account);
                        }
                    }
                }
                else if(tx_type == 5) // reward
                {
                    std::string topic_key = data["topic_key"].GetString();
                    
                    if(!is_base64_char(topic_key))
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    if(topic_key.length() != 44)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    std::shared_ptr<Topic> topic;
                    
                    if(!get_topic(topic_key, topic))
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    if(topic->get_owner() != account)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    std::shared_ptr<Reply> reply(new Reply(tx_id, 1, ""));
                    reply->set_owner(account);
                    
                    if(topic->m_reply_list.size() >= 1000)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    uint64 amount = data["amount"].GetUint64();
                    
                    if(amount == 0)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    if(topic->get_balance() < amount)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    std::string reply_to_key = data["reply_to"].GetString();
                    
                    if(!is_base64_char(reply_to_key))
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    if(reply_to_key.length() != 44)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    std::shared_ptr<Reply> reply_to;
                        
                    if(!topic->get_reply(reply_to_key, reply_to))
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    if(reply_to->type() != 0)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    reply->set_reply_to(reply_to);
                    topic->sub_balance(amount);
                    reply_to->add_balance(amount);
                    reply_to->get_owner()->add_balance(amount);
                    reply->add_balance(amount);
                    topic->m_reply_list.push_back(reply);
                }
                else
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
            }
            
            m_tx_map.insert(std::make_pair(tx_id, iter_block));
        }

        uint64 remain_balance = m_reserve_fund_account->get_balance();

        if(remain_balance >= 5000)
        {
            m_reserve_fund_account->sub_balance(5000);
            miner->add_balance(5000);
            iter_block->m_miner_reward = true;
        }
        else
        {
            iter_block->m_miner_reward = false;
        }

        m_block_changed = true;
    }
    
    auto pending_block = pending_chain->m_req_blocks[pending_chain->m_start];
    auto pending_id = pending_block->m_id;
    auto pending_hash = pending_block->m_hash;
    auto request = std::make_shared<Pending_Detail_Request>();
    request->m_owner_chain = pending_chain;
    rapidjson::Document doc;
    doc.SetObject();
    rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
    doc.AddMember("msg_type", net::p2p::MSG_BLOCK, allocator);
    doc.AddMember("msg_cmd", net::p2p::BLOCK_DETAIL_REQ, allocator);
    doc.AddMember("hash", rapidjson::StringRef(pending_hash.c_str()), allocator);
    ++request->m_try_num;
    LOG_DEBUG_INFO("pending_detail_request, id: %lu, hash: %s", pending_id, pending_hash.c_str());
    request->m_timer_id = m_timer_ctl.add_timer([=]() {
            if(request->m_try_num >= 3 && request->m_try_num >= request->m_attached_chains.size())
            {
                punish_detail_req(request);
            }
            else
            {
                auto last_peer = request->m_attached_chains.front()->m_peer;
                
                if(last_peer->m_connection->closed())
                {
                    request->m_attached_chains.pop_front();
                    
                    if(request->m_attached_chains.empty())
                    {
                        punish_detail_req(request);

                        return;
                    }
                }

                while(true)
                {
                    auto pchain = request->m_attached_chains.front();
                    request->m_attached_chains.pop_front();
                    request->m_attached_chains.push_back(pchain);
                    auto last_peer = request->m_attached_chains.front()->m_peer;
                    
                    if(last_peer->m_connection->closed())
                    {
                        request->m_attached_chains.pop_front();
                        
                        if(request->m_attached_chains.empty())
                        {
                            punish_detail_req(request);
                            
                            return;
                        }
                    }
                    else
                    {
                        break;
                    }
                }

                rapidjson::Document doc;
                doc.SetObject();
                rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
                doc.AddMember("msg_type", net::p2p::MSG_BLOCK, allocator);
                doc.AddMember("msg_cmd", net::p2p::BLOCK_DETAIL_REQ, allocator);
                doc.AddMember("hash", rapidjson::StringRef(pending_hash.c_str()), allocator);
                request->m_attached_chains.front()->m_peer->m_connection->send(doc);
                ++request->m_try_num;
            }
        }, 1);

    for(auto iter = m_brief_chains.begin(); iter != m_brief_chains.end(); ++iter)
    {
        auto &inner_chain = *iter;
        auto num = inner_chain->m_req_blocks.size();
        auto start_id = inner_chain->m_req_blocks[0]->m_id;
        auto end_id = inner_chain->m_req_blocks[num - 1]->m_id;
        
        if(pending_id > end_id || pending_id < start_id)
        {
            continue;
        }
        
        auto idx = pending_id - start_id;
        
        if(inner_chain->m_req_blocks[idx]->m_hash != pending_hash)
        {
            continue;
        }
        
        inner_chain->m_start = idx;
        inner_chain->m_detail_attached = request;
        request->m_attached_chains.push_back(inner_chain);
    }
    
    request->m_attached_chains.front()->m_peer->m_connection->send(doc);
    m_detail_request = request;
}

void Blockchain::rollback(uint64 block_id)
{
    uint64 cur_block_id  = m_cur_block->id();
    
    while(cur_block_id > block_id)
    {
        if(cur_block_id > (TOPIC_LIFE_TIME + 1))
        {
            auto iter = m_rollback_topics.find(cur_block_id - (TOPIC_LIFE_TIME + 1));

            if(iter == m_rollback_topics.end())
            {
                break;
            }
        }
        
        std::string block_data;
        std::string block_hash = m_cur_block->hash();
        leveldb::Status s = m_db->Get(leveldb::ReadOptions(), block_hash, &block_data);
        
        if(!s.ok())
        {
            LOG_FATAL("rollback, leveldb read failed, block_id: %lu, block_hash: %s, reason: %s", \
                      cur_block_id, block_hash.c_str(), s.ToString().c_str());
            
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
        
        rapidjson::Document doc;
        const char *block_data_str = block_data.c_str();
        doc.Parse(block_data_str);
        
        if(doc.HasParseError())
        {
            LOG_FATAL("rollback, parse block data failed, block_id: %lu, block_hash: %s, reason: %s", \
                      cur_block_id, block_hash.c_str(), GetParseError_En(doc.GetParseError()));

            ASKCOIN_EXIT(EXIT_FAILURE);
        }

        if(!doc.IsObject())
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
        
        const rapidjson::Value &data = doc["data"];
        const rapidjson::Value &tx_ids = data["tx_ids"];
        const rapidjson::Value &tx = doc["tx"];
        int32 tx_num = tx_ids.Size();
        
        if(tx.Size() != tx_num)
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
        
        std::shared_ptr<Account> miner = m_cur_block->get_miner();

        if(!miner)
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }

        LOG_DEBUG_INFO("rollback, id: %lu, hash: %s", cur_block_id, block_hash.c_str());
        
        if(m_cur_block->m_miner_reward)
        {
            m_reserve_fund_account->add_balance(5000);
            miner->sub_balance(5000);
        }

        if(tx_num <= 0)
        {
            ASKCOIN_TRACE;
            goto proc_tx_end;
        }
        
        for(int32 i = tx_num - 1; i >= 0; --i)
        {
            std::string tx_id = tx_ids[i].GetString();
            const rapidjson::Value &tx_node = tx[i];
            const rapidjson::Value &data = tx_node["data"];
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            data.Accept(writer);
            
            //base64 44 bytes length
            if(tx_id.length() != 44)
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }

            std::string tx_id_verify = coin_hash_b64(buffer.GetString(), buffer.GetSize());
            
            if(tx_id != tx_id_verify)
            {
                LOG_FATAL("rollback, verify tx data from leveldb failed, block_id: %lu, block_hash: %s, tx_id: %s", \
                          cur_block_id, block_hash.c_str(), tx_id.c_str());

                ASKCOIN_EXIT(EXIT_FAILURE);
            }
            
            std::string pubkey = data["pubkey"].GetString();
            
            if(pubkey.length() != 88)
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }

            m_tx_map.erase(tx_id);
            uint32 tx_type = data["type"].GetUint();
            
            if(tx_type == 1) // register account
            {
                const rapidjson::Value &sign_data = data["sign_data"];
                std::string register_name = sign_data["name"].GetString();
                std::string referrer_pubkey = sign_data["referrer"].GetString();
                std::shared_ptr<Account> referrer;
                get_account(referrer_pubkey, referrer);
                std::shared_ptr<Account> referrer_referrer = referrer->get_referrer();
                referrer->add_balance(2);
                miner->sub_balance(1);
                
                if(!referrer_referrer)
                {
                    if(referrer->id() > 1)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    m_reserve_fund_account->sub_balance(1);
                }
                else
                {
                    referrer_referrer->sub_balance(1);
                }
                
                m_account_names.erase(register_name);
                m_account_by_pubkey.erase(pubkey);
            }
            else
            {
                std::shared_ptr<Account> account;
                get_account(pubkey, account);
                std::shared_ptr<Account> referrer = account->get_referrer();
                account->add_balance(2);
                miner->sub_balance(1);
                
                if(!referrer)
                {
                    if(account->id() > 1)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    m_reserve_fund_account->sub_balance(1);
                }
                else
                {
                    referrer->sub_balance(1);
                }
                
                if(tx_type == 2) // send coin
                {
                    uint64 amount = data["amount"].GetUint64();
                    std::string receiver_pubkey = data["receiver"].GetString();
                    std::shared_ptr<Account> receiver;
                    get_account(receiver_pubkey, receiver);
                    account->add_balance(amount);
                    receiver->sub_balance(amount);
                }
                else if(tx_type == 3) // new topic
                {
                    uint64 reward = data["reward"].GetUint64();
                    account->add_balance(reward);
                    account->m_topic_list.pop_back();
                    m_topic_list.pop_back();
                    m_topics.erase(tx_id);
                }
                else if(tx_type == 4) // reply
                {
                    std::string topic_key = data["topic_key"].GetString();
                    std::shared_ptr<Topic> topic;
                    get_topic(topic_key, topic);
                    topic->m_reply_list.pop_back();

                    if(topic->get_owner() != account)
                    {
                        auto &p = topic->m_members.back();
                        
                        if(p.first == tx_id)
                        {
                            account->m_joined_topic_list.pop_back();
                            topic->m_members.pop_back();
                        }
                    }
                }
                else if(tx_type == 5) // reward
                {
                    std::string topic_key = data["topic_key"].GetString();
                    std::shared_ptr<Topic> topic;
                    get_topic(topic_key, topic);
                    uint64 amount = data["amount"].GetUint64();
                    std::string reply_to_key = data["reply_to"].GetString();
                    std::shared_ptr<Reply> reply_to;
                    topic->get_reply(reply_to_key, reply_to);
                    topic->add_balance(amount);
                    reply_to->sub_balance(amount);
                    reply_to->get_owner()->sub_balance(amount);
                    topic->m_reply_list.pop_back();
                }
                else
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
            }
        }
        
    proc_tx_end:
        if(cur_block_id > (TOPIC_LIFE_TIME + 1))
        {
            auto &topic_list = m_rollback_topics[cur_block_id - (TOPIC_LIFE_TIME + 1)];

            for(auto topic : topic_list)
            {
                m_topics.insert(std::make_pair(topic->key(), topic));
                topic->get_owner()->m_topic_list.push_front(topic);
                m_topic_list.push_front(topic);
                uint64 balance = topic->get_balance();
                        
                if(balance > 0)
                {
                    m_reserve_fund_account->sub_balance(balance);
                }

                for(auto &p : topic->m_members)
                {
                    p.second->m_joined_topic_list.push_front(topic);
                }
            }

            auto tx_pair = m_rollback_txs[cur_block_id - (TOPIC_LIFE_TIME + 1)];
                
            for(auto _tx_id : tx_pair.second)
            {
                m_tx_map.insert(std::make_pair(_tx_id, tx_pair.first));
            }
                
            m_rollback_topics.erase(cur_block_id - (TOPIC_LIFE_TIME + 1));
            m_rollback_txs.erase(cur_block_id - (TOPIC_LIFE_TIME + 1));
        }

        m_cur_block = m_cur_block->get_parent();
        cur_block_id  = m_cur_block->id();
    }
    
    if(cur_block_id > block_id)
    {
        uint64 iter_id = cur_block_id;
        auto iter_block = m_cur_block;
        uint32 count = 0;
        std::list<std::shared_ptr<Block>> block_list;
        std::unordered_map<std::string, std::shared_ptr<Topic>> topics;
        std::unordered_map<uint64, std::list<std::shared_ptr<Topic>>> rollback_topics;
        std::unordered_map<uint64, std::pair<std::shared_ptr<Block>, std::list<std::string>>> rollback_txs;

        while(iter_id > 1)
        {
            iter_block = iter_block->get_parent();
            iter_id = iter_block->id();
            block_list.push_front(iter_block);
        
            if(++count > TOPIC_LIFE_TIME)
            {
                break;
            }
        }
    
        if(count > TOPIC_LIFE_TIME)
        {
            uint64 diff = cur_block_id - block_id - 1;
        
            if(diff > 0)
            {
                while(iter_id > 1)
                {
                    iter_block = iter_block->get_parent();
                    iter_id = iter_block->id();
                    block_list.push_front(iter_block);

                    if(++count > TOPIC_LIFE_TIME + diff)
                    {
                        break;
                    }
                }
            }

            for(; count > TOPIC_LIFE_TIME; --count)
            {
                iter_block = block_list.front();
                uint64 cur_block_id = iter_block->id();
                std::string block_data;
                std::string block_hash = iter_block->hash();
                leveldb::Status s = m_db->Get(leveldb::ReadOptions(), iter_block->hash(), &block_data);
                
                if(!s.ok())
                {
                    LOG_FATAL("rollback, leveldb read failed, block_id: %lu, block_hash: %s, reason: %s", cur_block_id, block_hash.c_str(), s.ToString().c_str());

                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
            
                rapidjson::Document doc;
                const char *block_data_str = block_data.c_str();
                doc.Parse(block_data_str);
        
                if(doc.HasParseError())
                {
                    LOG_FATAL("rollback, parse block data failed, block_id: %lu, block_hash: %s, reason: %s", cur_block_id, block_hash.c_str(), \
                              GetParseError_En(doc.GetParseError()));

                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(!doc.IsObject())
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                {
                    std::list<std::shared_ptr<Topic>> value;
                    rollback_topics.insert(std::make_pair(cur_block_id, value));
                }
            
                {
                    std::pair<std::shared_ptr<Block>, std::list<std::string>> value;
                    rollback_txs.insert(std::make_pair(cur_block_id, value));
                }
            
                auto &topic_list = rollback_topics[cur_block_id];
                auto &tx_pair = rollback_txs[cur_block_id];
                tx_pair.first = iter_block;
                const rapidjson::Value &data = doc["data"];
                const rapidjson::Value &tx_ids = data["tx_ids"];
                const rapidjson::Value &tx = doc["tx"];
                uint32 tx_num = tx_ids.Size();
                
                if(tx.Size() != tx_num)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                for(uint32 i = 0; i < tx_num; ++i)
                {
                    std::string tx_id = tx_ids[i].GetString();
                    const rapidjson::Value &tx_node = tx[i];
                    const rapidjson::Value &data = tx_node["data"];
                    rapidjson::StringBuffer buffer;
                    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
                    data.Accept(writer);
                
                    //base64 44 bytes length
                    if(tx_id.length() != 44)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                
                    std::string tx_id_verify = coin_hash_b64(buffer.GetString(), buffer.GetSize());
            
                    if(tx_id != tx_id_verify)
                    {
                        LOG_FATAL("rollback, tx_id != tx_id_verify, block_id: %lu, block_hash: %s, tx_id: %s", \
                                  cur_block_id, block_hash.c_str(), tx_id.c_str());
                    
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    tx_pair.second.push_front(tx_id);
                    std::string pubkey = data["pubkey"].GetString();
                    uint32 tx_type = data["type"].GetUint();
                
                    if(tx_type == 1 || tx_type == 2)
                    {
                        continue;
                    }
                
                    std::shared_ptr<Account> account;
                    get_account(pubkey, account);
                
                    if(tx_type == 3) // new topic
                    {
                        uint64 reward = data["reward"].GetUint64();
                        std::string topic_data = data["topic"].GetString();
                        std::shared_ptr<Topic> topic(new Topic(tx_id, topic_data, cur_block_id, reward));
                        topic->set_owner(account);
                        topic_list.push_front(topic);
                        topics.insert(std::make_pair(tx_id, topic));
                    }
                    else if(tx_type == 4) // reply
                    {
                        std::string topic_key = data["topic_key"].GetString();
                        auto iter = topics.find(topic_key);
                    
                        if(iter == topics.end())
                        {
                            continue;
                        }
                    
                        std::shared_ptr<Topic> topic = iter->second;
                        std::string reply_data = data["reply"].GetString();
                        std::shared_ptr<Reply> reply(new Reply(tx_id, 0, reply_data));
                        reply->set_owner(account);
                        topic->m_reply_list.push_back(reply);
                    
                        if(data.HasMember("reply_to"))
                        {
                            std::string reply_to_key = data["reply_to"].GetString();
                            std::shared_ptr<Reply> reply_to;
                            topic->get_reply(reply_to_key, reply_to);
                            reply->set_reply_to(reply_to);
                        }
                    
                        if(topic->get_owner() != account)
                        {
                            topic->add_member(tx_id, account);
                        }
                    }
                    else if(tx_type == 5) // reward
                    {
                        std::string topic_key = data["topic_key"].GetString();
                        auto iter = topics.find(topic_key);
                    
                        if(iter == topics.end())
                        {
                            continue;
                        }
                    
                        std::shared_ptr<Topic> topic = iter->second;
                        std::shared_ptr<Reply> reply(new Reply(tx_id, 1, ""));
                        reply->set_owner(account);
                        uint64 amount = data["amount"].GetUint64();
                        std::string reply_to_key = data["reply_to"].GetString();
                        std::shared_ptr<Reply> reply_to;
                        topic->get_reply(reply_to_key, reply_to);
                        reply->set_reply_to(reply_to);
                        topic->sub_balance(amount);
                        reply_to->add_balance(amount);
                        reply->add_balance(amount);
                        topic->m_reply_list.push_back(reply);
                    }
                    else
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                }
            
                block_list.pop_front();
            }
        
            while(!block_list.empty())
            {
                iter_block = block_list.front();
                uint64 cur_block_id = iter_block->id();
                std::string block_data;
                std::string block_hash = iter_block->hash();
                leveldb::Status s = m_db->Get(leveldb::ReadOptions(), iter_block->hash(), &block_data);
                
                if(!s.ok())
                {
                    LOG_FATAL("rollback, leveldb read failed, block_id: %lu, block_hash: %s, reason: %s", cur_block_id, block_hash.c_str(), s.ToString().c_str());

                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
            
                rapidjson::Document doc;
                const char *block_data_str = block_data.c_str();
                doc.Parse(block_data_str);
        
                if(doc.HasParseError())
                {
                    LOG_FATAL("rollback, parse block data failed, block_id: %lu, block_hash: %s, reason: %s", cur_block_id, block_hash.c_str(), \
                              GetParseError_En(doc.GetParseError()));

                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(!doc.IsObject())
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                const rapidjson::Value &data = doc["data"];
                const rapidjson::Value &tx_ids = data["tx_ids"];
                const rapidjson::Value &tx = doc["tx"];
                uint32 tx_num = tx_ids.Size();
                
                if(tx.Size() != tx_num)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                for(uint32 i = 0; i < tx_num; ++i)
                {
                    std::string tx_id = tx_ids[i].GetString();
                    const rapidjson::Value &tx_node = tx[i];
                    const rapidjson::Value &data = tx_node["data"];
                    rapidjson::StringBuffer buffer;
                    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
                    data.Accept(writer);
                
                    //base64 44 bytes length
                    if(tx_id.length() != 44)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                
                    std::string tx_id_verify = coin_hash_b64(buffer.GetString(), buffer.GetSize());
            
                    if(tx_id != tx_id_verify)
                    {
                        LOG_FATAL("rollback, tx_id != tx_id_verify, block_id: %lu, block_hash: %s, tx_id: %s", \
                                  cur_block_id, block_hash.c_str(), tx_id.c_str());
                    
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                
                    std::string pubkey = data["pubkey"].GetString();
                    uint32 tx_type = data["type"].GetUint();
                
                    if(tx_type == 1 || tx_type == 2 || tx_type == 3)
                    {
                        continue;
                    }
                
                    std::shared_ptr<Account> account;
                    get_account(pubkey, account);
                
                    if(tx_type == 4) // reply
                    {
                        std::string topic_key = data["topic_key"].GetString();
                        auto iter = topics.find(topic_key);
                    
                        if(iter == topics.end())
                        {
                            continue;
                        }
                    
                        std::shared_ptr<Topic> topic = iter->second;
                        std::string reply_data = data["reply"].GetString();
                        std::shared_ptr<Reply> reply(new Reply(tx_id, 0, reply_data));
                        reply->set_owner(account);
                        topic->m_reply_list.push_back(reply);
                    
                        if(data.HasMember("reply_to"))
                        {
                            std::string reply_to_key = data["reply_to"].GetString();
                            std::shared_ptr<Reply> reply_to;
                            topic->get_reply(reply_to_key, reply_to);
                            reply->set_reply_to(reply_to);
                        }
                    
                        if(topic->get_owner() != account)
                        {
                            topic->add_member(tx_id, account);
                        }
                    }
                    else if(tx_type == 5) // reward
                    {
                        std::string topic_key = data["topic_key"].GetString();
                        auto iter = topics.find(topic_key);
                    
                        if(iter == topics.end())
                        {
                            continue;
                        }
                    
                        std::shared_ptr<Topic> topic = iter->second;
                        std::shared_ptr<Reply> reply(new Reply(tx_id, 1, ""));
                        reply->set_owner(account);
                        uint64 amount = data["amount"].GetUint64();
                        std::string reply_to_key = data["reply_to"].GetString();
                        std::shared_ptr<Reply> reply_to;
                        topic->get_reply(reply_to_key, reply_to);
                        reply->set_reply_to(reply_to);
                        topic->sub_balance(amount);
                        reply_to->add_balance(amount);
                        reply->add_balance(amount);
                        topic->m_reply_list.push_back(reply);
                    }
                    else
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                }
            
                block_list.pop_front();
            }
        }
        
        while(cur_block_id > block_id)
        {
            std::string block_data;
            std::string block_hash = m_cur_block->hash();
            leveldb::Status s = m_db->Get(leveldb::ReadOptions(), block_hash, &block_data);
            
            if(!s.ok())
            {
                LOG_FATAL("rollback, leveldb read failed, block_id: %lu, block_hash: %s, reason: %s", \
                          cur_block_id, block_hash.c_str(), s.ToString().c_str());

                ASKCOIN_EXIT(EXIT_FAILURE);
            }
        
            rapidjson::Document doc;
            const char *block_data_str = block_data.c_str();
            doc.Parse(block_data_str);
        
            if(doc.HasParseError())
            {
                LOG_FATAL("rollback, parse block data failed, block_id: %lu, block_hash: %s, reason: %s", \
                          cur_block_id, block_hash.c_str(), GetParseError_En(doc.GetParseError()));

                ASKCOIN_EXIT(EXIT_FAILURE);
            }

            if(!doc.IsObject())
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
            
            const rapidjson::Value &data = doc["data"];
            const rapidjson::Value &tx_ids = data["tx_ids"];
            const rapidjson::Value &tx = doc["tx"];
            int32 tx_num = tx_ids.Size();
        
            if(tx.Size() != tx_num)
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
        
            std::shared_ptr<Account> miner = m_cur_block->get_miner();
            
            if(!miner)
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
            
            if(m_cur_block->m_miner_reward)
            {
                m_reserve_fund_account->add_balance(5000);
                miner->sub_balance(5000);
            }

            if(tx_num <= 0)
            {
                ASKCOIN_TRACE;
                goto proc_tx_end_1;
            }

            for(int32 i = tx_num - 1; i >= 0; --i)
            {
                std::string tx_id = tx_ids[i].GetString();
                const rapidjson::Value &tx_node = tx[i];
                const rapidjson::Value &data = tx_node["data"];
                rapidjson::StringBuffer buffer;
                rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
                data.Accept(writer);
            
                //base64 44 bytes length
                if(tx_id.length() != 44)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                std::string tx_id_verify = coin_hash_b64(buffer.GetString(), buffer.GetSize());
            
                if(tx_id != tx_id_verify)
                {
                    LOG_FATAL("rollback, verify tx data from leveldb failed, block_id: %lu, block_hash: %s, tx_id: %s", \
                              cur_block_id, block_hash.c_str(), tx_id.c_str());

                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
            
                std::string pubkey = data["pubkey"].GetString();
            
                if(pubkey.length() != 88)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                m_tx_map.erase(tx_id);
                uint32 tx_type = data["type"].GetUint();
            
                if(tx_type == 1) // register account
                {
                    const rapidjson::Value &sign_data = data["sign_data"];
                    std::string register_name = sign_data["name"].GetString();
                    std::string referrer_pubkey = sign_data["referrer"].GetString();
                    std::shared_ptr<Account> referrer;
                    get_account(referrer_pubkey, referrer);
                    std::shared_ptr<Account> referrer_referrer = referrer->get_referrer();
                    referrer->add_balance(2);
                    miner->sub_balance(1);
                
                    if(!referrer_referrer)
                    {
                        if(referrer->id() > 1)
                        {
                            ASKCOIN_EXIT(EXIT_FAILURE);
                        }

                        m_reserve_fund_account->sub_balance(1);
                    }
                    else
                    {
                        referrer_referrer->sub_balance(1);
                    }
                
                    m_account_names.erase(register_name);
                    m_account_by_pubkey.erase(pubkey);
                }
                else
                {
                    std::shared_ptr<Account> account;
                    get_account(pubkey, account);
                    std::shared_ptr<Account> referrer = account->get_referrer();
                    account->add_balance(2);
                    miner->sub_balance(1);
                
                    if(!referrer)
                    {
                        if(account->id() > 1)
                        {
                            ASKCOIN_EXIT(EXIT_FAILURE);
                        }

                        m_reserve_fund_account->sub_balance(1);
                    }
                    else
                    {
                        referrer->sub_balance(1);
                    }
                
                    if(tx_type == 2) // send coin
                    {
                        uint64 amount = data["amount"].GetUint64();
                        std::string receiver_pubkey = data["receiver"].GetString();
                        std::shared_ptr<Account> receiver;
                        get_account(receiver_pubkey, receiver);
                        account->add_balance(amount);
                        receiver->sub_balance(amount);
                    }
                    else if(tx_type == 3) // new topic
                    {
                        uint64 reward = data["reward"].GetUint64();
                        account->add_balance(reward);
                        account->m_topic_list.pop_back();
                        m_topic_list.pop_back();
                        m_topics.erase(tx_id);
                    }
                    else if(tx_type == 4) // reply
                    {
                        std::string topic_key = data["topic_key"].GetString();
                        std::shared_ptr<Topic> topic;
                        get_topic(topic_key, topic);
                        topic->m_reply_list.pop_back();
                        
                        if(topic->get_owner() != account)
                        {
                            auto &p = topic->m_members.back();
                            
                            if(p.first == tx_id)
                            {
                                account->m_joined_topic_list.pop_back();
                                topic->m_members.pop_back();
                            }
                        }
                    }
                    else if(tx_type == 5) // reward
                    {
                        std::string topic_key = data["topic_key"].GetString();
                        std::shared_ptr<Topic> topic;
                        get_topic(topic_key, topic);
                        uint64 amount = data["amount"].GetUint64();
                        std::string reply_to_key = data["reply_to"].GetString();
                        std::shared_ptr<Reply> reply_to;
                        topic->get_reply(reply_to_key, reply_to);
                        topic->add_balance(amount);
                        reply_to->sub_balance(amount);
                        reply_to->get_owner()->sub_balance(amount);
                        topic->m_reply_list.pop_back();
                    }
                    else
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                }
            }

        proc_tx_end_1:
            if(cur_block_id > (TOPIC_LIFE_TIME + 1))
            {
                auto &topic_list = rollback_topics[cur_block_id - (TOPIC_LIFE_TIME + 1)];
                    
                for(auto topic : topic_list)
                {
                    m_topics.insert(std::make_pair(topic->key(), topic));
                    topic->get_owner()->m_topic_list.push_front(topic);
                    m_topic_list.push_front(topic);
                    uint64 balance = topic->get_balance();
                        
                    if(balance > 0)
                    {
                        m_reserve_fund_account->sub_balance(balance);
                    }

                    for(auto &p : topic->m_members)
                    {
                        p.second->m_joined_topic_list.push_front(topic);
                    }
                }

                auto tx_pair = rollback_txs[cur_block_id - (TOPIC_LIFE_TIME + 1)];
                
                for(auto _tx_id : tx_pair.second)
                {
                    m_tx_map.insert(std::make_pair(_tx_id, tx_pair.first));
                }
                    
                rollback_topics.erase(cur_block_id - (TOPIC_LIFE_TIME + 1));
                rollback_txs.erase(cur_block_id - (TOPIC_LIFE_TIME + 1));
            }

            m_cur_block = m_cur_block->get_parent();
            cur_block_id  = m_cur_block->id();
        }
    }
}
