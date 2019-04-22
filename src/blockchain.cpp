#include <netinet/in.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fstream>
#include "leveldb/comparator.h"
#include "leveldb/write_batch.h"
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
#include "rapidjson/ostreamwrapper.h"
#include "rapidjson/istreamwrapper.h"
#include "net/p2p/node.hpp"
#include "net/p2p/message.hpp"
#include "net/api/wsock_node.hpp"

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
    m_last_mine_time = 0;
}

Blockchain::~Blockchain()
{
}

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
    
    return (uint8)hash_arr[zero_char_num] < 1 << 8 - zero_remain_bit;
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
    
    if(cur_block_id > (2 * TOPIC_LIFE_TIME + 1))
    {
        m_rollback_txs.erase(cur_block_id - (2 * TOPIC_LIFE_TIME + 1));
    }

    m_rollback_txs.erase(cur_block_id - (TOPIC_LIFE_TIME + 1));
    auto &tx_pair = m_rollback_txs[cur_block_id - (TOPIC_LIFE_TIME + 1)];
    uint64 id = cur_block_id - TOPIC_LIFE_TIME - 1;
    auto iter = m_block_by_id.find(id);
    
    if(iter == m_block_by_id.end())
    {
        return true;
    }
    
    auto &expired_block = iter->second;
    std::string block_data;
    leveldb::Status s = m_db->Get(leveldb::ReadOptions(), expired_block->hash(), &block_data);
            
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
    
    tx_pair.first = expired_block;
    
    for(rapidjson::Value::ConstValueIterator iter = tx_ids.Begin(); iter != tx_ids.End(); ++iter)
    {
        std::string tx_id = iter->GetString();
        tx_pair.second.push_front(tx_id);
                
        if(m_tx_map.erase(tx_id) != 1)
        {
            return false;
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
    
    if(cur_block_id > (2 * TOPIC_LIFE_TIME + 1))
    {
        m_rollback_topics.erase(cur_block_id - (2 * TOPIC_LIFE_TIME + 1));
    }
    
    m_rollback_topics.erase(cur_block_id - (TOPIC_LIFE_TIME + 1));
    auto &topic_list = m_rollback_topics[cur_block_id - (TOPIC_LIFE_TIME + 1)];
    
    while(!m_topic_list.empty())
    {
        std::shared_ptr<Topic> topic = m_topic_list.front();
        uint64 topic_block_id = topic->m_block->id();
        
        if(topic_block_id + TOPIC_LIFE_TIME < cur_block_id)
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
        std::unique_lock<std::mutex> lock(p2p_node->m_score_mutex);
        auto &peer_scores = p2p_node->m_peer_scores;
        
        while(peer_scores.size() > 1000)
        {
            auto peer_score = *peer_scores.rbegin();
            p2p_node->del_peer_score(peer_score);
        }

        for(auto iter = peer_scores.begin(); iter != peer_scores.end(); ++iter)
        {
            std::shared_ptr<Peer_Score> peer_score = *iter;
            rapidjson::Value peer_info(rapidjson::kObjectType);
            peer_info.AddMember("host", rapidjson::StringRef(peer_score->m_addr.m_host.c_str()), allocator);
            peer_info.AddMember("port", peer_score->m_addr.m_port, allocator);
            peer_info.AddMember("score", peer_score->m_score, allocator);
            peers.PushBack(peer_info, allocator);
        }
        
        lock.unlock();
        doc.AddMember("utc", time(NULL), allocator);
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

void Blockchain::do_mine()
{
    while(!m_stop.load(std::memory_order_relaxed))
    {
        if(!m_need_remine.load(std::memory_order_acquire))
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        
        std::list<std::shared_ptr<tx::Tx>> mined_txs;
        uint64 cur_block_id, cur_block_utc;
        uint32 zero_bits;
        std::string cur_block_hash, miner_key;
        std::atomic<uint64> mine_id_2 {0};
    remine:
        {
            std::lock_guard<std::mutex> guard(m_mine_mutex);
            mined_txs = std::move(m_mined_txs);
            mine_id_2.store(m_mine_id_1.load(std::memory_order_relaxed), std::memory_order_relaxed);
            cur_block_id = m_mine_cur_block_id;
            cur_block_utc = m_mine_cur_block_utc;
            cur_block_hash = m_mine_cur_block_hash;
            zero_bits = m_mine_zero_bits;
            miner_key = m_miner_privkey;
            m_need_remine.store(false, std::memory_order_relaxed);
        }

        char privk[32];
        fly::base::base64_decode(miner_key.c_str(), miner_key.length(), privk, 32);
        CKey miner_priv_key;
        miner_priv_key.Set(privk, privk + 32, false);
        CPubKey miner_pub_key = miner_priv_key.GetPubKey();
        std::string miner_pub_key_b64 = fly::base::base64_encode(miner_pub_key.begin(), miner_pub_key.size());
        
        auto doc_ptr = std::make_shared<rapidjson::Document>();
        rapidjson::Document &doc = *doc_ptr;
        doc.SetObject();
        rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
        doc.AddMember("hash", "", allocator);
        doc.AddMember("sign", "", allocator);
        rapidjson::Value data(rapidjson::kObjectType);
        data.AddMember("id", cur_block_id + 1, allocator);
        data.AddMember("utc", time(NULL), allocator);
        data.AddMember("version", ASKCOIN_VERSION, allocator);
        data.AddMember("zero_bits", zero_bits, allocator);
        data.AddMember("pre_hash", rapidjson::Value(cur_block_hash.c_str(), allocator), allocator);
        data.AddMember("miner", rapidjson::Value(miner_pub_key_b64.c_str(), allocator), allocator);
        rapidjson::Value tx_ids(rapidjson::kArrayType);
        
        for(auto tx : mined_txs)
        {
            tx_ids.PushBack(rapidjson::Value(tx->m_id.c_str(), allocator), allocator);
        }

        data.AddMember("tx_ids", tx_ids, allocator);
        rapidjson::Value nonce(rapidjson::kArrayType);
        nonce.PushBack(0, allocator);
        nonce.PushBack(0, allocator);
        nonce.PushBack(0, allocator);
        nonce.PushBack(0, allocator);
        data.AddMember("nonce", nonce, allocator);
        char hash_raw[32];
        
        for(uint64 i = 0; i < (uint64)-1; ++i)
        {
            for(uint64 j = 0; j < (uint64)-1; ++j)
            {
                for(uint64 k = 0; k < (uint64)-1; ++k)
                {
                    for(uint64 m = 0; m < (uint64)-1; ++m)
                    {
                        if(m_stop.load(std::memory_order_relaxed))
                        {
                            return;
                        }
                        
                        if(m_need_remine.load(std::memory_order_acquire))
                        {
                            goto remine;
                        }
                        
                        uint64 utc = time(NULL);
                        
                        if(utc < cur_block_utc)
                        {
                            utc = cur_block_utc;
                        }
                        
                        data["utc"].SetUint64(utc);
                        data["nonce"][0] = m;
                        data["nonce"][1] = k;
                        data["nonce"][2] = j;
                        data["nonce"][3] = i;
                        rapidjson::StringBuffer buffer;
                        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
                        data.Accept(writer);
                        uint32 buf[16] = {0};
                        char *p = (char*)buf;
                        coin_hash(buffer.GetString(), buffer.GetSize(), p);
                        char * ptr = buffer.Push(16);
                        memcpy(ptr, "another_32_bytes", 16);
                        coin_hash(buffer.GetString(), buffer.GetSize(), p + 32);
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

                        ptr = buffer.Push(88);
                        std::string p_b64 = fly::base::base64_encode(p, 64);
                        memcpy(ptr, p_b64.data(), 88);
                        coin_hash(buffer.GetString(), buffer.GetSize(), hash_raw);
                        uint32 zero_char_num = zero_bits / 8;
                        uint32 zero_remain_bit = 0;

                        for(uint32 i = 0; i < zero_char_num; ++i)
                        {
                            if(hash_raw[i] != 0)
                            {
                                goto try_next;
                            }
                        }

                        zero_remain_bit = zero_bits % 8;
                        
                        if(zero_remain_bit == 0)
                        {
                            goto mine_success;
                        }
                            
                        if((uint8)hash_raw[zero_char_num] < 1 << 8 - zero_remain_bit)
                        {
                            goto mine_success;
                        }

                    try_next:
                        ;
                    }
                }
            }
        }
        
    mine_success:
        std::string hex_hash = fly::base::byte2hexstr(hash_raw, 32);
        std::string block_hash = fly::base::base64_encode(hash_raw, 32);
        LOG_DEBUG_INFO("mine successfully, zero_bits: %u, block_id: %lu, block_hash: %s (hex: %s)", \
                       zero_bits, cur_block_id + 1, block_hash.c_str(), hex_hash.c_str());
        doc["hash"].SetString(block_hash.c_str(), allocator);
        std::vector<unsigned char> sign_vec;

        if(!miner_priv_key.Sign(uint256(std::vector<unsigned char>(hash_raw, hash_raw + 32)), sign_vec))
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
        
        std::string block_sign = fly::base::base64_encode(&sign_vec[0], sign_vec.size());
        doc["sign"].SetString(block_sign.c_str(), allocator);
        doc.AddMember("data", data, allocator);
        rapidjson::Value doc_tx(rapidjson::kArrayType);
        
        for(auto tx : mined_txs)
        {
            rapidjson::Document &doc = *tx->m_doc;
            rapidjson::Value tx_node(rapidjson::kObjectType);
            tx_node.AddMember("sign", rapidjson::Value().CopyFrom(doc["sign"], allocator), allocator);
            tx_node.AddMember("data", rapidjson::Value().CopyFrom(doc["data"], allocator), allocator);
            doc_tx.PushBack(tx_node, allocator);
        }
        
        doc.AddMember("tx", doc_tx, allocator);
        {
            std::lock_guard<std::mutex> guard(m_mine_mutex);
            m_mine_doc = doc_ptr;
            m_mine_id_2.store(mine_id_2.load(std::memory_order_relaxed), std::memory_order_relaxed);
        }
        
        m_mine_success.store(true, std::memory_order_release);
    }
}

void Blockchain::do_command(std::shared_ptr<Command> command)
{
    fly::base::Scope_CB cb([]() {
        fflush(stdout);
    });

    if(command->m_cmd == "top100")
    {
        uint32 cnt = 0;
        char title[5][15] = {"rank", "account_name", "account_id", "avatar", "balance"};
        printf("-------------------------------------------------------------\n");
        printf("%-5s\t%-15s\t%-10s\t%-7s\t%-22s\n", title[0], title[1], title[2], title[3], title[4]);
        printf("-------------------------------------------------------------\n");
        
        for(auto iter = m_account_by_rich.begin(); iter != m_account_by_rich.end(); ++iter)
        {
            if(++cnt > 100)
            {
                break;
            }
            
            auto account = *iter;
            char raw_name[16] = {0};
            fly::base::base64_decode(account->name().c_str(), account->name().length(), raw_name, 16);
            printf("%-5u\t%-15s\t%-10lu\t%-7u\t%-22lu\n", cnt, raw_name, account->id(), account->avatar(), account->get_balance());
        }
        
        printf("-------------------------------------------------------------\n");
        printf(">");
    }
    else if(command->m_cmd == "clear_uv_tx")
    {
        m_uv_1_txs.clear();
        m_uv_2_txs.clear();
        printf("clear_uv_tx successfully\n>");
    }
    else if(command->m_cmd == "clear_peer")
    {
        rapidjson::Document peer_doc;
        peer_doc.SetObject();
        rapidjson::Document::AllocatorType &peer_allocator = peer_doc.GetAllocator();
        rapidjson::Value peers(rapidjson::kArrayType);
        peer_doc.AddMember("utc", time(NULL), peer_allocator);
        peer_doc.AddMember("peers", peers, peer_allocator);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        peer_doc.Accept(writer);
        leveldb::Status s = m_db->Put(leveldb::WriteOptions(), "peer_score", buffer.GetString());
        
        if(!s.ok())
        {
            printf("clear_peer failed, reason: %s\n", s.ToString().c_str());
        } else {
            printf("clear_peer successfully\n");
        }
        
        printf(">");
    }
    else if(command->m_cmd == "myinfo")
    {
        std::unique_lock<std::mutex> lock(m_mine_mutex);
        std::string miner_privkey = m_miner_privkey;
        lock.unlock();
        
        if(miner_privkey.empty())
        {
            printf("you need import_privkey first\n>");
            return;
        }
        
        char privk[32];
        fly::base::base64_decode(miner_privkey.c_str(), miner_privkey.length(), privk, 32);
        CKey miner_priv_key;
        miner_priv_key.Set(privk, privk + 32, false);
        CPubKey miner_pub_key = miner_priv_key.GetPubKey();
        std::string miner_pub_key_b64 = fly::base::base64_encode(miner_pub_key.begin(), miner_pub_key.size());
        std::shared_ptr<Account> account;
        
        if(!get_account(miner_pub_key_b64, account))
        {
            printf("you need reg_account first\n>");
            return;
        }

        char raw_name[16] = {0};
        fly::base::base64_decode(account->name().c_str(), account->name().length(), raw_name, 16);
        printf("your account's id: %lu\n", account->id());
        printf("your account's name: %s\n", raw_name);
        printf("your account's avatar: %u\n", account->avatar());
        printf("your account's balance: %lu ASK\n", account->get_balance());
        printf("your account's reg_block_id: %lu\n", account->block_id());
        printf("your account's question num: %u\n", account->m_topic_list.size());
        printf("your account's answer num: %u\n", account->m_joined_topic_list.size());
        auto referrer = account->get_referrer();
        
        if(referrer)
        {
            char raw_name[16] = {0};
            fly::base::base64_decode(referrer->name().c_str(), referrer->name().length(), raw_name, 16);
            printf("your account's referrer id: %lu\n", referrer->id());
            printf("your account's referrer name: %s\n", raw_name);
        }
        
        printf(">");
    }
    else if(command->m_cmd == "info")
    {
        net::api::Wsock_Node *wsock_node = net::api::Wsock_Node::instance();
        std::unique_lock<std::mutex> lock(wsock_node->m_mutex);
        printf("wsock connection count: %u\n", wsock_node->m_users.size());
        lock.unlock();
        auto p2p_node = net::p2p::Node::instance();
        std::unique_lock<std::mutex> lock_p2p(p2p_node->m_peer_mutex);
        printf("peer connection count: %u\n", p2p_node->m_peers.size());
        lock_p2p.unlock();
        printf("account count: %u\n", m_account_by_id.size());
        auto iter_block = m_cur_block;
        std::unordered_set<std::string> miner_pubkeys;
        uint32 block_num = 0;
        
        while(iter_block->id() != 0)
        {
            miner_pubkeys.insert(iter_block->miner_pubkey());

            if(++block_num >= 10000)
            {
                break;
            }

            iter_block = iter_block->get_parent();
        }
        
        printf("miner count (latest 10000 blocks): %u\n", miner_pubkeys.size());
        printf("miner total: %u\n", m_miner_pubkeys.size());
        printf("topic count: %u\n", m_topic_list.size());
        printf("uv tx count: %u\n", m_uv_2_txs.size());
        printf("cur block id: %lu\n", m_cur_block->id());
        auto block_hash = m_cur_block->hash();
        printf("cur block hash: %s\n", block_hash.c_str());
        char hash_raw[32];
        fly::base::base64_decode(block_hash.c_str(), block_hash.length(), hash_raw, 32);
        std::string hex_hash = fly::base::byte2hexstr(hash_raw, 32);
        printf("cur block hash (hex): %s\n>", hex_hash.c_str());
    }
    else if(command->m_cmd == "lock")
    {
        if(m_is_locked)
        {
            printf("can't repeat locking\n>");
            return;
        }
        
        std::string password = command->m_params[0];
        
        if(password.empty())
        {
            printf("password can't be empty\n>");
            return;
        }

        char sha1_buf[20] = {0};
        fly::base::sha1(password.c_str(), password.length(), sha1_buf, 20);
        m_lock_password.assign(sha1_buf, 20);
        m_is_locked = true;
        printf("your wallet is locked\n>");
    }
    else if(command->m_cmd == "unlock")
    {
        if(!m_is_locked)
        {
            printf("can't repeat unlocking\n>");
            return;
        }
        
        std::string password = command->m_params[0];

        if(password.empty())
        {
            printf("password can't be empty\n>");
            return;
        }

        char sha1_buf[20] = {0};
        fly::base::sha1(password.c_str(), password.length(), sha1_buf, 20);
        std::string password_sha1(sha1_buf, 20);
        
        if(password_sha1 != m_lock_password)
        {
            printf("password is not correct\n>");
            return;
        }
        
        m_is_locked = false;
        printf("your wallet is unlocked\n>");
    }
    else if(command->m_cmd == "enable_mine")
    {
        std::string enable = command->m_params[0];
        
        if(enable != "true" && enable != "false")
        {
            printf("the param of enable_mine must be true or false\n>");
            return;
        }
        
        if(enable == "true")
        {
            m_enable_mine.store(true, std::memory_order_relaxed);
            m_block_changed = true;
            printf("mine status: enable\n>");
        }
        else
        {
            m_enable_mine.store(false, std::memory_order_relaxed);
            printf("mine status: disable\n>");
        }
    }
    else if(command->m_cmd == "get_balance")
    {
        std::unique_lock<std::mutex> lock(m_mine_mutex);
        std::string miner_privkey = m_miner_privkey;
        lock.unlock();
        
        if(miner_privkey.empty())
        {
            printf("you need import_privkey first\n>");
            return;
        }
        
        char privk[32];
        fly::base::base64_decode(miner_privkey.c_str(), miner_privkey.length(), privk, 32);
        CKey miner_priv_key;
        miner_priv_key.Set(privk, privk + 32, false);
        CPubKey miner_pub_key = miner_priv_key.GetPubKey();
        std::string miner_pub_key_b64 = fly::base::base64_encode(miner_pub_key.begin(), miner_pub_key.size());
        std::shared_ptr<Account> account;
        
        if(!get_account(miner_pub_key_b64, account))
        {
            printf("you need reg_account first\n>");
            return;
        }

        printf("your account's balance: %lu ASK\n>", account->get_balance());
    }
    else if(command->m_cmd == "send_coin")
    {
        if(m_is_locked)
        {
            printf("you need unlock your wallet first\n>");
            return;
        }
        
        uint64 account_id;
        uint64 amount;
        fly::base::string_to(command->m_params[0], account_id);
        fly::base::string_to(command->m_params[1], amount);
        std::unique_lock<std::mutex> lock(m_mine_mutex);
        std::string miner_privkey = m_miner_privkey;
        lock.unlock();
        
        if(miner_privkey.empty())
        {
            printf("you need import_privkey first\n>");
            return;
        }
        
        char privk[32];
        fly::base::base64_decode(miner_privkey.c_str(), miner_privkey.length(), privk, 32);
        CKey miner_priv_key;
        miner_priv_key.Set(privk, privk + 32, false);
        CPubKey miner_pub_key = miner_priv_key.GetPubKey();
        std::string miner_pub_key_b64 = fly::base::base64_encode(miner_pub_key.begin(), miner_pub_key.size());
        std::shared_ptr<Account> account;
        
        if(!get_account(miner_pub_key_b64, account))
        {
            printf("you need reg_account first\n>");
            return;
        }
        
        if(account->get_balance() < amount + 2 + account->m_uv_spend)
        {
            printf("your account's balance is insufficient\n>");
            return;
        }
        
        if(account_id == 0)
        {
            printf("can't send coin to reserve_fund\n>");
            return;
        }
        
        std::shared_ptr<Account> receiver;
        auto iter = m_account_by_id.find(account_id);
        
        if(iter == m_account_by_id.end())
        {
            printf("receiver account doesn't exist\n>");
            return;
        }

        receiver = iter->second;
        uint64 utc = time(NULL);
        uint64 cur_block_id = m_cur_block->id();
        auto doc_ptr = std::make_shared<rapidjson::Document>();
        auto &p2p_doc = *doc_ptr;
        p2p_doc.SetObject();
        rapidjson::Document::AllocatorType &p2p_allocator = p2p_doc.GetAllocator();
        p2p_doc.AddMember("msg_type", net::p2p::MSG_TX, p2p_allocator);
        p2p_doc.AddMember("msg_cmd", net::p2p::TX_BROADCAST, p2p_allocator);
        rapidjson::Value data(rapidjson::kObjectType);
        data.AddMember("type", 2, p2p_allocator);
        data.AddMember("pubkey", rapidjson::Value(miner_pub_key_b64.c_str(), p2p_allocator), p2p_allocator);
        data.AddMember("utc", utc, p2p_allocator);
        data.AddMember("block_id", cur_block_id + 1, p2p_allocator);
        data.AddMember("fee", 2, p2p_allocator);
        data.AddMember("amount", amount, p2p_allocator);
        std::string memo;

        if(command->m_param_num > 2)
        {
            memo = command->m_params[2];

            if(memo.length() > 60)
            {
                printf("memo is too long\n>");
                return;
            }
            
            std::string memo_b64 = fly::base::base64_encode(memo.c_str(), memo.length());
            data.AddMember("memo", rapidjson::Value(memo_b64.c_str(), p2p_allocator), p2p_allocator);
        }
        
        data.AddMember("receiver", rapidjson::Value(receiver->pubkey().c_str(), p2p_allocator), p2p_allocator);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        data.Accept(writer);
        char raw_hash[32] = {0};
        coin_hash(buffer.GetString(), buffer.GetSize(), raw_hash);
        std::string tx_id = fly::base::base64_encode(raw_hash, 32);

        if(m_tx_map.find(tx_id) != m_tx_map.end())
        {
            printf("this tx already exist\n>");
            return;
        }
        
        if(m_uv_tx_ids.find(tx_id) != m_uv_tx_ids.end())
        {
            printf("this tx already exist\n>");
            return;
        }
        
        std::vector<unsigned char> sign_vec;
        
        if(!miner_priv_key.Sign(uint256(std::vector<unsigned char>(raw_hash, raw_hash + 32)), sign_vec))
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
        
        std::string sign = fly::base::base64_encode(&sign_vec[0], sign_vec.size());
        p2p_doc.AddMember("sign", rapidjson::Value(sign.c_str(), p2p_allocator), p2p_allocator);
        p2p_doc.AddMember("data", data, p2p_allocator);
        
        std::shared_ptr<tx::Tx_Send> tx_send(new tx::Tx_Send);
        tx_send->m_id = tx_id;
        tx_send->m_type = 2;
        tx_send->m_utc = utc;
        tx_send->m_doc = doc_ptr;
        tx_send->m_pubkey = miner_pub_key_b64;
        tx_send->m_block_id = cur_block_id + 1;
        tx_send->m_receiver_pubkey = receiver->pubkey();
        tx_send->m_amount = amount;
        m_uv_tx_ids.insert(tx_id);
        m_uv_2_txs.push_back(tx_send);
        account->m_uv_spend += amount + 2;
        net::p2p::Node::instance()->broadcast(p2p_doc);
        printf("send_coin has been successfully broadcast, please wait the miner to confirm\n>");
    }
    else if(command->m_cmd == "gen_reg_sign")
    {
        auto &raw_name = command->m_params[0];
        std::unique_lock<std::mutex> lock(m_mine_mutex);
        std::string miner_privkey = m_miner_privkey;
        lock.unlock();
        
        if(miner_privkey.empty())
        {
            printf("you need import_privkey first\n>");
            return;
        }
        
        uint32 len = raw_name.length();
        printf("acount_name: %s, length: %u\n", raw_name.c_str(), len);
        
        if(len > 15 || len == 0)
        {
            printf("account_name's length is invalid, can't exceed 15 bytes\n>");
            return;
        }
        
        for(uint32 i = 0; i < len; ++i)
        {
            if(std::isspace(static_cast<unsigned char>(raw_name[i])))
            {
                printf("account_name can't contain space\n>");
                return;
            }
        }

        std::string register_name = fly::base::base64_encode(raw_name.c_str(), len);
        
        if(account_name_exist(register_name))
        {
            printf("account_name already exists\n>");
            return;
        }
        
        if(m_uv_account_names.find(register_name) != m_uv_account_names.end())
        {
            printf("account_name already exists\n>");
            return;
        }

        char privk[32];
        fly::base::base64_decode(miner_privkey.c_str(), miner_privkey.length(), privk, 32);
        CKey miner_priv_key;
        miner_priv_key.Set(privk, privk + 32, false);
        CPubKey miner_pub_key = miner_priv_key.GetPubKey();
        std::string miner_pub_key_b64 = fly::base::base64_encode(miner_pub_key.begin(), miner_pub_key.size());
        std::shared_ptr<Account> referrer;
        
        if(!get_account(miner_pub_key_b64, referrer))
        {
            printf("you need reg_account first\n>");
            return;
        }
        
        if(referrer->get_balance() < 2 + referrer->m_uv_spend)
        {
            printf("your account's balance is insufficient\n>");
            return;
        }
        
        uint64 cur_block_id = m_cur_block->id();
        rapidjson::Document doc;
        doc.SetObject();
        rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
        rapidjson::Value sign_data(rapidjson::kObjectType);
        sign_data.AddMember("block_id", cur_block_id + 1, allocator);
        sign_data.AddMember("fee", 2, allocator);
        sign_data.AddMember("name", rapidjson::StringRef(register_name.c_str()), allocator);
        sign_data.AddMember("referrer", rapidjson::StringRef(miner_pub_key_b64.c_str()), allocator);

        {
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            sign_data.Accept(writer);
            char raw_hash[32] = {0};
            coin_hash(buffer.GetString(), buffer.GetSize(), raw_hash);
            std::vector<unsigned char> sign_vec;
            
            if(!miner_priv_key.Sign(uint256(std::vector<unsigned char>(raw_hash, raw_hash + 32)), sign_vec))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }

            std::string sign = fly::base::base64_encode(&sign_vec[0], sign_vec.size());
            doc.AddMember("sign", rapidjson::Value(sign.c_str(), allocator), allocator);
            doc.AddMember("sign_data", sign_data, allocator);
        }
        
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        doc.Accept(writer);
        printf("gen_reg_sign successfully, reg_sign:\n%s\n>", buffer.GetString());
    }
    else if(command->m_cmd == "reg_account")
    {
        auto &raw_name = command->m_params[0];
        uint32 avatar = 0;
        fly::base::string_to(command->m_params[1], avatar);
        std::string reg_sign = command->m_params[2];
        std::unique_lock<std::mutex> lock(m_mine_mutex);
        std::string miner_privkey = m_miner_privkey;
        lock.unlock();
        
        if(miner_privkey.empty())
        {
            printf("you need import_privkey first\n>");
            return;
        }
        
        uint32 len = raw_name.length();

        if(len > 15 || len == 0)
        {
            printf("account_name's length is invalid, can't exceed 15 bytes\n>");
            return;
        }
        
        for(uint32 i = 0; i < len; ++i)
        {
            if(std::isspace(static_cast<unsigned char>(raw_name[i])))
            {
                printf("account_name can't contain space\n>");
                return;
            }
        }

        std::string register_name = fly::base::base64_encode(raw_name.c_str(), len);
        
        if(account_name_exist(register_name))
        {
            printf("account_name already exists\n>");
            return;
        }
        
        if(m_uv_account_names.find(register_name) != m_uv_account_names.end())
        {
            printf("account_name already exists\n>");
            return;
        }
        
        char privk[32];
        fly::base::base64_decode(miner_privkey.c_str(), miner_privkey.length(), privk, 32);
        CKey miner_priv_key;
        miner_priv_key.Set(privk, privk + 32, false);
        CPubKey miner_pub_key = miner_priv_key.GetPubKey();
        std::string miner_pub_key_b64 = fly::base::base64_encode(miner_pub_key.begin(), miner_pub_key.size());
        uint64 cur_block_id = m_cur_block->id();
        std::shared_ptr<Account> exist_account;

        if(get_account(miner_pub_key_b64, exist_account))
        {
            printf("your privkey is already registered\n>");
            return;
        }
        
        if(m_uv_account_pubkeys.find(miner_pub_key_b64) != m_uv_account_pubkeys.end())
        {
            printf("your privkey is already registered\n>");
            return;
        }

        if(avatar < 1 || avatar > 100)
        {
            printf("avatar must be in range from 1 to 100\n>");
            return;
        }
        
        rapidjson::Document ref_doc;
        ref_doc.Parse(reg_sign.c_str());
        
        if(ref_doc.HasParseError())
        {
            printf("parse reg_sign failed, reason: %s\n>", GetParseError_En(ref_doc.GetParseError()));
            return;
        }
        
        if(!ref_doc.IsObject())
        {
            printf("parse reg_sign failed\n>");
            return;
        }

        if(!ref_doc.HasMember("sign"))
        {
            printf("parse reg_sign failed\n>");
            return;
        }

        if(!ref_doc["sign"].IsString())
        {
            printf("parse reg_sign failed\n>");
            return;
        }
        
        if(!ref_doc.HasMember("sign_data"))
        {
            printf("parse reg_sign failed\n>");
            return;
        }

        rapidjson::Value &sign_data = ref_doc["sign_data"];
        
        if(!sign_data.IsObject())
        {
            printf("parse reg_sign failed\n>");
            return;
        }
        
        std::string ref_sign = ref_doc["sign"].GetString();
        
        if(!is_base64_char(ref_sign))
        {
            printf("parse reg_sign failed\n>");
            return;
        }

        std::string sign_hash;
        {
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            sign_data.Accept(writer);
            sign_hash = coin_hash_b64(buffer.GetString(), buffer.GetSize());
        }

        if(!sign_data.HasMember("block_id"))
        {
            printf("parse reg_sign failed\n>");
            return;
        }

        if(!sign_data["block_id"].IsUint64())
        {
            printf("parse reg_sign failed\n>");
            return;
        }
                    
        if(!sign_data.HasMember("name"))
        {
            printf("parse reg_sign failed\n>");
            return;
        }

        if(!sign_data["name"].IsString())
        {
            printf("parse reg_sign failed\n>");
            return;
        }
                    
        if(!sign_data.HasMember("referrer"))
        {
            printf("parse reg_sign failed\n>");
            return;
        }

        if(!sign_data["referrer"].IsString())
        {
            printf("parse reg_sign failed\n>");
            return;
        }
                    
        if(!sign_data.HasMember("fee"))
        {
            printf("parse reg_sign failed\n>");
            return;
        }

        if(!sign_data["fee"].IsUint64())
        {
            printf("parse reg_sign failed\n>");
            return;
        }
        
        uint64 block_id = sign_data["block_id"].GetUint64();
        std::string reg_name = sign_data["name"].GetString();
        std::string referrer_pubkey = sign_data["referrer"].GetString();
        uint64 fee = sign_data["fee"].GetUint64();

        if(block_id == 0)
        {
            printf("parse reg_sign failed\n>");
            return;
        }

        if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 1 + 100)
        {
            printf("parse reg_sign failed, block_id is expired\n>");
            return;
        }
        
        if(fee != 2)
        {
            printf("parse reg_sign failed\n>");
            return;
        }
        
        if(!is_base64_char(referrer_pubkey))
        {
            printf("parse reg_sign failed\n>");
            return;
        }

        if(referrer_pubkey.length() != 88)
        {
            printf("parse reg_sign failed\n>");
            return;
        }
                
        if(!verify_sign(referrer_pubkey, sign_hash, ref_sign))
        {
            printf("parse reg_sign failed\n>");
            return;
        }

        if(!is_base64_char(reg_name))
        {
            printf("parse reg_sign failed\n>");
            return;
        }

        if(reg_name.length() > 20 || reg_name.length() < 4)
        {
            printf("parse reg_sign failed\n>");
            return;
        }

        if(reg_name != register_name)
        {
            printf("parse reg_sign failed, name: %s(base64) is not the same as the name in sign: %s(base64)\n>", register_name.c_str(), reg_name.c_str());
            return;
        }
        
        std::shared_ptr<Account> referrer;
        
        if(!get_account(referrer_pubkey, referrer))
        {
            printf("parse reg_sign failed, referrer account does not exist\n>");
            return;
        }
        
        if(referrer->get_balance() < 2 + referrer->m_uv_spend)
        {
            printf("parse reg_sign failed, referrer account's balance is insufficient\n>");
            return;
        }

        uint64 utc = time(NULL);
        auto doc_ptr = std::make_shared<rapidjson::Document>();
        auto &p2p_doc = *doc_ptr;
        p2p_doc.SetObject();
        rapidjson::Document::AllocatorType &p2p_allocator = p2p_doc.GetAllocator();
        p2p_doc.AddMember("msg_type", net::p2p::MSG_TX, p2p_allocator);
        p2p_doc.AddMember("msg_cmd", net::p2p::TX_BROADCAST, p2p_allocator);
        rapidjson::Value data(rapidjson::kObjectType);
        data.AddMember("type", 1, p2p_allocator);
        data.AddMember("pubkey", rapidjson::Value(miner_pub_key_b64.c_str(), p2p_allocator), p2p_allocator);
        data.AddMember("utc", utc, p2p_allocator);
        data.AddMember("avatar", avatar, p2p_allocator);
        data.AddMember("sign", rapidjson::Value().CopyFrom(ref_doc["sign"], p2p_allocator), p2p_allocator);
        data.AddMember("sign_data", rapidjson::Value().CopyFrom(sign_data, p2p_allocator), p2p_allocator);
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        data.Accept(writer);
        char raw_hash[32] = {0};
        coin_hash(buffer.GetString(), buffer.GetSize(), raw_hash);
        std::string tx_id = fly::base::base64_encode(raw_hash, 32);

        if(m_tx_map.find(tx_id) != m_tx_map.end())
        {
            printf("this tx already exist\n>");
            return;
        }
        
        if(m_uv_tx_ids.find(tx_id) != m_uv_tx_ids.end())
        {
            printf("this tx already exist\n>");
            return;
        }
        
        std::vector<unsigned char> sign_vec;
        
        if(!miner_priv_key.Sign(uint256(std::vector<unsigned char>(raw_hash, raw_hash + 32)), sign_vec))
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
        
        std::string sign = fly::base::base64_encode(&sign_vec[0], sign_vec.size());
        p2p_doc.AddMember("sign", rapidjson::Value(sign.c_str(), p2p_allocator), p2p_allocator);
        p2p_doc.AddMember("data", data, p2p_allocator);
        
        std::shared_ptr<tx::Tx_Reg> tx_reg(new tx::Tx_Reg);
        tx_reg->m_id = tx_id;
        tx_reg->m_type = 1;
        tx_reg->m_utc = utc;
        tx_reg->m_doc = doc_ptr;
        tx_reg->m_pubkey = miner_pub_key_b64;
        tx_reg->m_block_id = block_id;
        tx_reg->m_register_name = register_name;
        tx_reg->m_avatar = avatar;
        tx_reg->m_referrer_pubkey = referrer_pubkey;
        m_uv_tx_ids.insert(tx_id);
        m_uv_account_names.insert(register_name);
        m_uv_account_pubkeys.insert(miner_pub_key_b64);
        m_uv_2_txs.push_back(tx_reg);
        referrer->m_uv_spend += 2;
        net::p2p::Node::instance()->broadcast(p2p_doc);
        printf("reg_account has been successfully broadcast, please wait the miner to confirm\n>");
    } 
    else if(command->m_cmd == "gen_privkey")
    {
        CKey key;
        key.MakeNewKey(false);
        CPubKey pubkey = key.GetPubKey();
        std::string key_b64 = fly::base::base64_encode(key.begin(), key.size());
        std::string pubkey_b64 = fly::base::base64_encode(pubkey.begin(), pubkey.size());
        printf("please remember your privkey: %s\n>", key_b64.c_str());
    }
    else if(command->m_cmd == "import_privkey")
    {
        if(command->m_params[0].length() != 44)
        {
            printf("your privkey is invalid\n>");
            return;
        }
        
        char privk[32];
        uint32 len = fly::base::base64_decode(command->m_params[0].c_str(), command->m_params[0].length(), privk, 32);

        if(len != 32)
        {
            printf("your privkey is invalid\n>");
            return;
        }
        
        CKey miner_priv_key;
        miner_priv_key.Set(privk, privk + 32, false);

        if(!miner_priv_key.IsValid())
        {
            printf("your privkey is invalid\n>");
            return;
        }
        
        CPubKey miner_pub_key = miner_priv_key.GetPubKey();
        
        if(!miner_pub_key.IsFullyValid())
        {
            printf("your privkey is invalid\n>");
            return;
        }
        
        std::unique_lock<std::mutex> lock(m_mine_mutex);
        m_miner_privkey = command->m_params[0];
        lock.unlock();
        m_miner_pubkey = fly::base::base64_encode(miner_pub_key.begin(), miner_pub_key.size());
        printf("import_privkey successfully, miner_pub_key: %s\n>", m_miner_pubkey.c_str());
        m_block_changed = true;
    }
}

void Blockchain::do_message()
{
    while(!m_stop.load(std::memory_order_relaxed))
    {
        bool peer_empty = false;
        bool wsock_empty = false;
        std::list<std::unique_ptr<fly::net::Message<Json>>> peer_messages;
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

        bool command_empty = false;
        std::list<std::shared_ptr<Command>> commands;
        
        if(m_commands.pop(commands))
        {
            for(auto cmd : commands)
            {
                do_command(cmd);
            }
        }
        else
        {
            command_empty = true;
        }
        
        bool called = m_timer_ctl.run();

        if(m_block_changed)
        {
            sync_block();
            do_uv_tx();
            m_block_changed = false;
        }

        std::atomic<uint64> mine_id_2 {0};
        std::shared_ptr<rapidjson::Document> doc_ptr;
        static std::atomic<uint64> last_mine_id {0};
        
        if(m_mine_success.load(std::memory_order_acquire))
        {
            std::unique_lock<std::mutex> lock(m_mine_mutex);
            doc_ptr = m_mine_doc;
            mine_id_2.store(m_mine_id_2.load(std::memory_order_relaxed), std::memory_order_relaxed);
            m_mine_success.store(false, std::memory_order_relaxed);
            lock.unlock();
            
            if(mine_id_2.load(std::memory_order_relaxed) == m_mine_id_1.load(std::memory_order_relaxed))
            {
                if(last_mine_id.load(std::memory_order_relaxed) != mine_id_2.load(std::memory_order_relaxed))
                {
                    if(!m_enable_mine.load(std::memory_order_relaxed))
                    {
                        continue;
                    }
                    
                    lock.lock();
                    
                    if(m_miner_privkey.empty())
                    {
                        continue;
                    }

                    lock.unlock();
                    std::shared_ptr<Account> miner;
                    
                    if(!get_account(m_miner_pubkey, miner))
                    {
                        continue;
                    }
                    
                    mined_new_block(doc_ptr);
                    last_mine_id.store(mine_id_2.load(std::memory_order_relaxed), std::memory_order_relaxed);
                }
            }
        }
        else if(peer_empty && wsock_empty && !called && command_empty)
        {
            RandAddSeedSleep();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
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
    m_mine_thread.join();
    m_score_thread.join();
}

bool Blockchain::start(std::string db_path, bool repair_db)
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
    options.create_if_missing = true;
    options.max_open_files = 50000;
    options.max_file_size = 100 * (1 << 20);
    leveldb::Status s;

    if(repair_db)
    {
        s = leveldb::RepairDB(db_path, options);
        
        if(!s.ok())
        {
            CONSOLE_LOG_FATAL("repairdb failed: %s", s.ToString().c_str());

            return false;
        }

        CONSOLE_LOG_INFO("repairdb successfully!");

        return true;
    }
    
    s = leveldb::DB::Open(options, db_path, &m_db);
    
    if(!s.ok())
    {
        CONSOLE_LOG_FATAL("open leveldb failed: %s", s.ToString().c_str());
        
        return false;
    }
    
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
    
    bool merge_point_exist = false;
    bool merge_point_export = false;
    bool merge_point_import = false;
    std::list<Child_Block> block_list;
    std::shared_ptr<Block> the_most_difficult_block;
    
    if(m_merge_point)
    {
        if(m_merge_point->m_import_block_id > 0)
        {
            merge_point_import = true;
        }

        if(m_merge_point->m_export_block_id > 0)
        {
            merge_point_export = true;
        }
    }
    
    if(!merge_point_import)
    {
        std::string block_0;
        s = m_db->Get(leveldb::ReadOptions(), "0", &block_0);
    
        if(!s.ok())
        {
            if(!s.IsNotFound())
            {
                CONSOLE_LOG_FATAL("read block_0 from leveldb failed: %s", s.ToString().c_str());

                return false;
            }

            std::string genesis_block_data = "{\"hash\":\"\",\"sign\":\"\",\"data\":{\"id\":0,\"utc\":1518926400,\"version\":1,\"zero_bits\":0,\"intro\":\"Askcoin is a gift for those who love freedom.\",\"init_account\":{\"account\":\"lichuan\",\"id\":1,\"avatar\":1,\"pubkey\":\"BH6PNUv9anrjG9GekAd+nus+emyYm1ClCT0gIut1O7A3w6uRl7dAihcD8HvKh+IpOopcgQAzkYxQZ+cxT+32WdM=\"},\"author\":{\"name\":\"Chuan Li\",\"country\":\"China\",\"github\":\"https://github.com/lichuan\",\"mail\":\"308831759@qq.com\",\"belief\":\"In the beginning, God created the heavens and the earth.\"}},\"children\":[]}";
        
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
            uint32 buf[16] = {0};
            char *p = (char*)buf;
            coin_hash(buffer_1.GetString(), buffer_1.GetSize(), p);
            char * ptr = buffer_1.Push(16);
            memcpy(ptr, "another_32_bytes", 16);
            coin_hash(buffer_1.GetString(), buffer_1.GetSize(), p + 32);
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
        
            ptr = buffer_1.Push(88);
            std::string p_b64 = fly::base::base64_encode(p, 64);
            memcpy(ptr, p_b64.data(), 88);
            std::string genesis_block_hash = coin_hash_b64(buffer_1.GetString(), buffer_1.GetSize());
            std::string sign_b64 = "MEQCIAe9Demds6XNev/smZ4QkOcwgwTLjZP2gsAOwmd6OEEhAiB8dDdN3YJYQJjxvQFN/WxcE5Fx1kA7MwTQ/UmycVS98w==";
            //sign_b64 = sign("", genesis_block_hash);
        
            doc["hash"].SetString(genesis_block_hash.c_str(), allocator);
            doc["sign"].SetString(sign_b64.c_str(), allocator);
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

        if(block_hash != "zM9M0jTCRJKnhU+RIbPUCqFPCKYwUO9n6gLrAeMLBKE=")
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
        std::string data_str(buffer.GetString(), buffer.GetSize());
    
        //base64 44 bytes length
        if(block_hash.length() != 44)
        {
            CONSOLE_LOG_FATAL("parse leveldb block 0 failed, hash length is not 44 bytes");

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
        m_reserve_fund_account = std::make_shared<Account>(0, reserve_fund_b64, "", 1, 0);
        std::shared_ptr<Account> author_account(new Account(1, account_b64, pubkey, 1, 0));
        m_account_by_id.insert(std::make_pair(0, m_reserve_fund_account));
        m_account_by_id.insert(std::make_pair(1, author_account));
        m_cur_account_id = 1;
        m_account_names.insert(reserve_fund_b64);
        m_account_names.insert(account_b64);
        uint64 total = (uint64)1000000000000UL;
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

        if(version != 1)
        {
            ASKCOIN_RETURN false;
        }
    
        if(zero_bits != 0)
        {
            ASKCOIN_RETURN false;
        }

        if(!verify_hash(block_hash, data_str, 0))
        {
            CONSOLE_LOG_FATAL("verify genesis block hash failed, hash: %s", block_hash.c_str());
            return false;
        }
        
        const rapidjson::Value &children = doc["children"];
        
        if(!children.IsArray())
        {
            ASKCOIN_RETURN false;
        }
        
        std::shared_ptr<Block> genesis_block(new Block(block_id, utc, version, zero_bits, block_hash));
        genesis_block->set_miner_pubkey(pubkey);
        genesis_block->m_in_main_chain = true;
        m_blocks.insert(std::make_pair(block_hash, genesis_block));
        m_block_by_id.insert(std::make_pair(0, genesis_block));
        the_most_difficult_block = genesis_block;

        for(rapidjson::Value::ConstValueIterator iter = children.Begin(); iter != children.End(); ++iter)
        {
            Child_Block child_block(genesis_block, iter->GetString());
            block_list.push_back(child_block);
        }
    }
    else
    {
        std::ifstream ifs(m_merge_point->m_import_path);
        rapidjson::IStreamWrapper isw(ifs);
        rapidjson::Document doc;
        doc.ParseStream(isw);

        if(doc.HasParseError())
        {
            CONSOLE_LOG_FATAL("merge_point import failed, import_path: %s, reason: %s", m_merge_point->m_import_path.c_str(), GetParseError_En(doc.GetParseError()));
            
            return false;
        }

        // todo
    }
    
    struct _Data
    {
        std::string m_block_hash;
        std::string m_block_data;
        uint32 m_zero_bits;
        bool m_finished;
    };
    
    fly::base::Lock_Queue<_Data> lock_q;
    std::atomic<bool> finished_signal {false};
    std::atomic<bool> error_signal {false};
    std::atomic<uint64> verify_cnt {1};
    int32 cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
    const int32 thread_num = cpu_num * 2;
    std::thread verify_threads[thread_num];
    CONSOLE_ONLY("verify_hash threads num: %u", thread_num);
    CONSOLE_ONLY("loading block, phase 1, please wait a moment......");
    
    for(int32 i = 0; i < thread_num; ++i)
    {
        verify_threads[i] = std::move(std::thread([&] {
            while(!finished_signal.load(std::memory_order_relaxed))
            {
                if(error_signal.load(std::memory_order_relaxed))
                {
                    return;
                }
                
                std::list<_Data> data_list;

                if(lock_q.pop(data_list))
                {
                    for(auto &d : data_list)
                    {
                        if(error_signal.load(std::memory_order_relaxed))
                        {
                            return;
                        }
                        
                        if(d.m_finished)
                        {
                            finished_signal.store(true, std::memory_order_relaxed);
                            return;
                        }
                        
                        if(!Blockchain::verify_hash(d.m_block_hash, d.m_block_data, d.m_zero_bits))
                        {
                            error_signal.store(true, std::memory_order_relaxed);
                            lock_q.pulse_notify_not_full();
                            CONSOLE_LOG_FATAL("verify block hash and zero_bits failed, hash: %s", d.m_block_hash.c_str());
                            return;
                        }
                        
                        uint64 _cnt = verify_cnt.fetch_add(1, std::memory_order_relaxed);

                        if(_cnt % 100 == 0)
                        {
                            CONSOLE_ONLY("verify_hash block from leveldb, %lu blocks have been verified", _cnt);
                        }
                    }
                }
            }
        }));
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

        if(!doc["hash"].IsString())
        {
            ASKCOIN_RETURN false;
        }

        if(!doc["sign"].IsString())
        {
            ASKCOIN_RETURN false;
        }
        
        std::string block_hash = doc["hash"].GetString();
        std::string block_sign = doc["sign"].GetString();

        if(!is_base64_char(block_hash))
        {
            ASKCOIN_RETURN false;
        }
            
        if(!is_base64_char(block_sign))
        {
            ASKCOIN_RETURN false;
        }

        if(block_hash.length() != 44)
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
        
        if(block_hash != child_block.m_hash)
        {
            ASKCOIN_RETURN false;
        }

        const rapidjson::Value &data = doc["data"];
        
        if(!data.IsObject())
        {
            ASKCOIN_RETURN false;
        }

        if(data.MemberCount() != 8)
        {
            ASKCOIN_RETURN false;
        }
        
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
        std::string miner_pubkey = data["miner"].GetString();
        
        if(!is_base64_char(miner_pubkey))
        {
            ASKCOIN_RETURN false;
        }

        if(miner_pubkey.length() != 88)
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

        if(zero_bits == 0 || zero_bits >= 256)
        {
            ASKCOIN_RETURN false;
        }
        
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
        
        if(utc_diff < 10)
        {
            if(zero_bits != parent_zero_bits + 1)
            {
                ASKCOIN_RETURN false;
            }
        }
        else if(utc_diff > 30)
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
        
        _Data _data;
        _data.m_block_hash = block_hash;
        _data.m_block_data = data_str;
        _data.m_zero_bits = zero_bits;
        _data.m_finished = false;
        lock_q.push(_data);
        std::shared_ptr<Block> cur_block(new Block(block_id, utc, version, zero_bits, block_hash));
        cur_block->set_parent(parent);
        cur_block->set_miner_pubkey(miner_pubkey);
        cur_block->add_difficulty_from(parent);
        
        if(m_blocks.find(block_hash) != m_blocks.end())
        {
            ASKCOIN_RETURN false;
        }
        
        cur_block->m_tx_num = tx_num;
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
        
        if(the_most_difficult_block->difficult_than_me(cur_block))
        {
            the_most_difficult_block = cur_block;
        }
        
        block_list.pop_front();

        if(error_signal.load(std::memory_order_relaxed))
        {
            for(int32 i = 0; i < thread_num; ++i)
            {
                verify_threads[i].join();
            }

            return false;
        }
    }
    
    _Data _data;
    _data.m_finished = true;
    lock_q.push(_data);
    
    while(!finished_signal.load(std::memory_order_relaxed))
    {
        if(error_signal.load(std::memory_order_relaxed))
        {
            for(int32 i = 0; i < thread_num; ++i)
            {
                verify_threads[i].join();
            }
            
            return false;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    
    for(int32 i = 0; i < thread_num; ++i)
    {
        verify_threads[i].join();
    }
    
    CONSOLE_ONLY("loading block, phase 2, please wait a moment......");
    std::list<std::shared_ptr<Block>> block_chain;
    std::shared_ptr<Block> iter_block = the_most_difficult_block;
    m_cur_block = the_most_difficult_block;
    m_most_difficult_block = the_most_difficult_block;
    
    while(iter_block->id() != 0)
    {
        iter_block->m_in_main_chain = true;
        block_chain.push_front(iter_block);
        iter_block = iter_block->get_parent();
    }
    
    // now, load tx in every block in order
    while(!block_chain.empty())
    {
        iter_block = block_chain.front();
        uint64 cur_block_id = iter_block->id();
        std::string block_hash = iter_block->hash();
        std::string block_data;
        s = m_db->Get(leveldb::ReadOptions(), block_hash, &block_data);
        
        if(!s.ok())
        {
            ASKCOIN_RETURN false;
        }
        
        std::shared_ptr<rapidjson::Document> doc_ptr = std::make_shared<rapidjson::Document>();
        auto &doc = *doc_ptr;
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

        uint64 utc = iter_block->utc();
        
        for(uint32 i = 0; i < tx_num; ++i)
        {
            std::string tx_id = tx_ids[i].GetString();
            
            // tx can not be repeated.
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
                    auto history = std::make_shared<History>(HISTORY_REFERRER_REWARD);
                    history->m_block_id = cur_block_id;
                    history->m_block_hash = block_hash;
                    history->m_change = 1;
                    history->m_target_id = referrer->id();
                    history->m_target_avatar = referrer->avatar();
                    history->m_target_name = referrer->name();
                    history->m_utc = utc;
                    history->m_tx_id = tx_id;
                    referrer_referrer->add_history(history);
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
                
                std::shared_ptr<Account> reg_account(new Account(++m_cur_account_id, register_name, pubkey, avatar, cur_block_id));
                m_account_names.insert(register_name);
                m_account_by_pubkey.insert(std::make_pair(pubkey, reg_account));
                m_account_by_id.insert(std::make_pair(m_cur_account_id, reg_account));
                reg_account->set_referrer(referrer);
                auto history = std::make_shared<History>(HISTORY_REG_FEE);
                history->m_block_id = cur_block_id;
                history->m_block_hash = block_hash;
                history->m_change = 2;
                
                // history->m_target_id = reg_account->id();
                // history->m_target_avatar = reg_account->avatar();
                // history->m_target_name = reg_account->name();
                
                history->m_utc = utc;
                history->m_tx_id = tx_id;
                referrer->add_history(history);
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
                    auto history = std::make_shared<History>(HISTORY_REFERRER_REWARD);
                    history->m_block_id = cur_block_id;
                    history->m_block_hash = block_hash;
                    history->m_change = 1;
                    history->m_target_id = account->id();
                    history->m_target_avatar = account->avatar();
                    history->m_target_name = account->name();
                    history->m_utc = utc;
                    history->m_tx_id = tx_id;
                    referrer->add_history(history);
                }

                auto history = std::make_shared<History>();
                history->m_block_id = cur_block_id;
                history->m_block_hash = block_hash;
                history->m_change = 2;
                history->m_utc = utc;
                history->m_tx_id = tx_id;
                account->add_history(history);
                
                if(tx_type == 2) // send coin
                {
                    history->m_type = HISTORY_SEND_FEE;
                    auto history_to = std::make_shared<History>(HISTORY_SEND_TO);
                    auto history_from = std::make_shared<History>(HISTORY_SEND_FROM);

                    if(data.HasMember("memo"))
                    {
                        if(!data["memo"].IsString())
                        {
                            ASKCOIN_RETURN false;
                        }
                        
                        std::string memo = data["memo"].GetString();
                        
                        if(memo.empty())
                        {
                            ASKCOIN_RETURN false;
                        }
                        
                        if(!is_base64_char(memo))
                        {
                            ASKCOIN_RETURN false;
                        }
                        
                        if(memo.length() > 80 || memo.length() < 4)
                        {
                            ASKCOIN_RETURN false;
                        }

                        history_from->m_memo = memo;
                        history_to->m_memo = memo;
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
                    history_to->m_block_id = cur_block_id;
                    history_to->m_block_hash = block_hash;
                    history_to->m_change = amount;
                    history_to->m_utc = utc;
                    history_to->m_target_id = receiver->id();
                    history_to->m_target_avatar = receiver->avatar();
                    history_to->m_target_name = receiver->name();
                    history_to->m_tx_id = tx_id;
                    account->add_history(history_to);
                    history_from->m_block_id = cur_block_id;
                    history_from->m_block_hash = block_hash;
                    history_from->m_change = amount;
                    history_from->m_utc = utc;
                    history_from->m_target_id = account->id();
                    history_from->m_target_avatar = account->avatar();
                    history_from->m_target_name = account->name();
                    history_from->m_tx_id = tx_id;
                    receiver->add_history(history_from);
                }
                else if(tx_type == 3) // new topic
                {
                    history->m_type = HISTORY_NEW_TOPIC_FEE;
                    
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

                    if(topic_data.length() < 4 || topic_data.length() > 1336)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    if(account->m_topic_list.size() >= 100)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    account->sub_balance(reward);
                    std::shared_ptr<Topic> topic(new Topic(tx_id, topic_data, iter_block, reward));
                    topic->set_owner(account);
                    account->m_topic_list.push_back(topic);
                    m_topic_list.push_back(topic);
                    m_topics.insert(std::make_pair(tx_id, topic));
                    auto history = std::make_shared<History>(HISTORY_NEW_TOPIC_REWARD);
                    history->m_block_id = cur_block_id;
                    history->m_block_hash = block_hash;
                    history->m_change = reward;
                    history->m_utc = utc;
                    history->m_tx_id = tx_id;
                    account->add_history(history);
                }
                else if(tx_type == 4) // reply
                {
                    history->m_type = HISTORY_REPLY_FEE;
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

                    if(reply_data.length() < 4 || reply_data.length() > 1336)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    std::shared_ptr<Reply> reply(new Reply(tx_id, 0, iter_block, reply_data));
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
                    history->m_type = HISTORY_REWARD_FEE;
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
                    
                    std::shared_ptr<Reply> reply(new Reply(tx_id, 1, iter_block, ""));
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

                    if(reply_to->get_owner() == account)
                    {
                        ASKCOIN_RETURN false;
                    }
                    
                    reply->set_reply_to(reply_to);
                    topic->sub_balance(amount);
                    reply_to->add_balance(amount);
                    reply_to->get_owner()->add_balance(amount);
                    reply->add_balance(amount);
                    topic->m_reply_list.push_back(reply);
                    auto history = std::make_shared<History>(HISTORY_REWARD_FROM);
                    history->m_block_id = cur_block_id;
                    history->m_block_hash = block_hash;
                    history->m_change = amount;
                    history->m_utc = utc;
                    history->m_target_id = account->id();
                    history->m_target_avatar = account->avatar();
                    history->m_target_name = account->name();
                    history->m_tx_id = tx_id;
                    reply_to->get_owner()->add_history(history);
                }
                else
                {
                    ASKCOIN_RETURN false;
                }
            }
            
            m_tx_map.insert(std::make_pair(tx_id, iter_block));
        }

        uint64 remain_balance = m_reserve_fund_account->get_balance();

        if(tx_num > 0)
        {
            miner->add_balance(tx_num);
            auto history = std::make_shared<History>(HISTORY_MINER_TX_REWARD);
            history->m_block_id = cur_block_id;
            history->m_block_hash = block_hash;
            history->m_change = tx_num;
            history->m_utc = utc;
            miner->add_history(history);
        }
        
        if(remain_balance >= 5000)
        {
            m_reserve_fund_account->sub_balance(5000);
            miner->add_balance(5000);
            iter_block->m_miner_reward = true;
            auto history = std::make_shared<History>(HISTORY_MINER_BLOCK_REWARD);
            history->m_block_id = cur_block_id;
            history->m_block_hash = block_hash;
            history->m_change = 5000;
            history->m_utc = utc;
            miner->add_history(history);
        }
        else
        {
            iter_block->m_miner_reward = false;
        }

        m_miner_pubkeys.insert(miner->pubkey());
        
        if(cur_block_id % 1000 == 0)
        {
            char hash_raw[32];
            fly::base::base64_decode(iter_block->hash().c_str(), iter_block->hash().length(), hash_raw, 32);
            std::string hex_hash = fly::base::byte2hexstr(hash_raw, 32);
            CONSOLE_ONLY("load block progress: cur_block_id: %lu, cur_block_hash: %s (hex: %s)", \
                   cur_block_id, iter_block->hash().c_str(), hex_hash.c_str());
        }

        m_block_by_id.insert(std::make_pair(cur_block_id, iter_block));
        block_chain.pop_front();
        
        if(block_chain.empty())
        {
            m_broadcast_doc = doc_ptr;
        }

        if(merge_point_export)
        {
            if(cur_block_id == m_merge_point->m_export_block_id)
            {
                if(block_hash != m_merge_point->m_export_block_hash)
                {
                    CONSOLE_LOG_FATAL("merge_point block not in the main chain, block_id equal but block_hash != m_merge_point->m_export_block_hash");
                    ASKCOIN_RETURN false;
                }

                merge_point_exist = true;
                break;
            }
            
            if(block_hash == m_merge_point->m_export_block_hash)
            {
                CONSOLE_LOG_FATAL("merge_point block not int the main chain, block_hash equal but cur_block_id != m_merge_point->m_export_block_id");
                ASKCOIN_RETURN false;
            }
        }
    }
    
    if(merge_point_export)
    {
        if(!merge_point_exist)
        {
            CONSOLE_LOG_FATAL("merge_point block not int the main chain");
            ASKCOIN_RETURN false;
        }

        if(!check_balance())
        {
            CONSOLE_LOG_FATAL("check_balance failed");
            ASKCOIN_RETURN false;
        }

        auto pos = std::string::npos;

        if((pos = m_merge_point->m_export_path.find_last_of('/')) != std::string::npos)
        {
            if(pos > 0)
            {
                auto export_dir = m_merge_point->m_export_path.substr(0, pos);

                if(fly::base::mkpath(export_dir) == -1)
                {
                    CONSOLE_LOG_FATAL("merge_point mkpath export_dir: %s failed, reason: %s", \
                                      export_dir.c_str(), strerror(errno));
                    ASKCOIN_RETURN false;
                }
            }
        }
        
        rapidjson::Document doc;
        doc.SetObject();
        std::ofstream ofs(m_merge_point->m_export_path);
        rapidjson::OStreamWrapper osw(ofs);
        rapidjson::Writer<rapidjson::OStreamWrapper> writer(osw);
        rapidjson::Document::AllocatorType &allocator = doc.GetAllocator();
        rapidjson::Value accounts(rapidjson::kArrayType);
        rapidjson::Value pow_arr(rapidjson::kArrayType);

        std::string block_data;
        s = m_db->Get(leveldb::ReadOptions(), m_merge_point->m_export_block_hash, &block_data);
        
        if(!s.ok())
        {
            ASKCOIN_RETURN false;
        }

        rapidjson::Document doc_export_block;
        const char *block_data_str = block_data.c_str();
        doc_export_block.Parse(block_data_str);
        
        if(doc_export_block.HasParseError())
        {
            ASKCOIN_RETURN false;
        }
        
        if(!doc_export_block.IsObject())
        {
            ASKCOIN_RETURN false;
        }
        
        doc_export_block["children"].Clear();
        rapidjson::StringBuffer buffer;
        {
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            doc_export_block.Accept(writer);
        }
        std::string export_block_data_str(buffer.GetString(), buffer.GetSize());

        doc.AddMember("block_id", m_merge_point->m_export_block_id, allocator);
        doc.AddMember("block_hash", rapidjson::StringRef(m_merge_point->m_export_block_hash.c_str()), allocator);
        doc.AddMember("doc", doc_export_block, allocator);
        auto mp_block = m_blocks[m_merge_point->m_export_block_hash];
        
        for(int32 i = 0; i < 9; ++i)
        {
            pow_arr.PushBack(mp_block->m_accum_pow.m_n32[i], allocator);
        }

        doc.AddMember("pow", pow_arr, allocator);
        rapidjson::Value total_miner(rapidjson::kArrayType);

        for(auto &miner_pubkey : m_miner_pubkeys)
        {
            total_miner.PushBack(rapidjson::StringRef(miner_pubkey.c_str()), allocator);
        }
        
        doc.AddMember("total_miner", total_miner, allocator);
        
        for(auto p : m_account_by_id)
        {
            rapidjson::Value obj(rapidjson::kObjectType);
            auto account = p.second;
            obj.AddMember("id", account->id(), allocator);
            obj.AddMember("name", rapidjson::StringRef(account->name().c_str()), allocator);
            obj.AddMember("avatar", account->avatar(), allocator);
            obj.AddMember("balance", account->get_balance(), allocator);
            obj.AddMember("pubkey", rapidjson::StringRef(account->pubkey().c_str()), allocator);
            obj.AddMember("block_id", account->block_id(), allocator);

            if(account->id() > 1)
            {
                auto referrer = account->get_referrer();
                obj.AddMember("referrer", rapidjson::StringRef(referrer->pubkey().c_str()), allocator);
            }

            accounts.PushBack(obj, allocator);
        }

        doc.AddMember("accounts", accounts, allocator);
        rapidjson::Value tx_map(rapidjson::kArrayType);
        std::unordered_map<std::string, std::shared_ptr<Block>> blocks;
        
        for(auto &p : m_tx_map)
        {
            auto &block = p.second;
            
            if(block->id() + 100 < m_merge_point->m_export_block_id + 1)
            {
                continue;
            }
            
            const std::string& block_hash = block->hash();
            
            if(blocks.find(block_hash) == blocks.end())
            {
                blocks.insert(std::make_pair(block_hash, block));
            }
            
            rapidjson::Value obj(rapidjson::kObjectType);
            obj.AddMember("block_id", block->id(), allocator);
            obj.AddMember("tx_id", rapidjson::StringRef(p.first.c_str()), allocator);
            tx_map.PushBack(obj, allocator);
        }
        
        doc.AddMember("tx_map", tx_map, allocator);
        rapidjson::Value topics(rapidjson::kArrayType);
        
        for(auto &topic : m_topic_list)
        {
            rapidjson::Value obj(rapidjson::kObjectType);
            obj.AddMember("key", rapidjson::StringRef(topic->key().c_str()), allocator);
            obj.AddMember("data", rapidjson::StringRef(topic->m_data.c_str()), allocator);
            obj.AddMember("balance", topic->get_balance(), allocator);
            obj.AddMember("total", topic->get_total(), allocator);
            obj.AddMember("owner", topic->get_owner()->id(), allocator);
            auto &block = topic->m_block;
            const std::string& block_hash = block->hash();
            
            if(blocks.find(block_hash) == blocks.end())
            {
                blocks.insert(std::make_pair(block_hash, block));
            }
            
            obj.AddMember("block_id", block->id(), allocator);
            rapidjson::Value members(rapidjson::kArrayType);

            for(auto member : topic->m_members)
            {
                members.PushBack(member.second->id(), allocator);
            }
            
            obj.AddMember("members", members, allocator);
            rapidjson::Value replies(rapidjson::kArrayType);
            
            for(auto &reply : topic->m_reply_list)
            {
                rapidjson::Value obj(rapidjson::kObjectType);
                obj.AddMember("key", rapidjson::StringRef(reply->key().c_str()), allocator);
                obj.AddMember("data", rapidjson::StringRef(reply->m_data.c_str()), allocator);
                obj.AddMember("balance", reply->get_balance(), allocator);
                obj.AddMember("type", reply->type(), allocator);
                obj.AddMember("owner", reply->get_owner()->id(), allocator);
                auto reply_to = reply->get_reply_to();
                
                if(reply_to)
                {
                    obj.AddMember("reply_to", rapidjson::StringRef(reply_to->key().c_str()), allocator);
                }
                
                auto &block = reply->m_block;
                const std::string& block_hash = block->hash();
                
                if(blocks.find(block_hash) == blocks.end())
                {
                    blocks.insert(std::make_pair(block_hash, block));
                }
                
                obj.AddMember("block_id", block->id(), allocator);
                replies.PushBack(obj, allocator);
            }
            
            obj.AddMember("replies", replies, allocator);
            topics.PushBack(obj, allocator);
        }
        
        doc.AddMember("topics", topics, allocator);
        rapidjson::Value block_arr(rapidjson::kArrayType);
        
        for(auto &p : blocks)
        {
            auto block = p.second;
            rapidjson::Value block_obj(rapidjson::kObjectType);
            block_obj.AddMember("id", block->id(), allocator);
            block_obj.AddMember("utc", block->utc(), allocator);
            block_obj.AddMember("version", block->version(), allocator);
            block_obj.AddMember("zero_bits", block->zero_bits(), allocator);
            block_obj.AddMember("hash", rapidjson::StringRef(block->hash().c_str()), allocator);
            block_arr.PushBack(block_obj, allocator);
        }
        
        doc.AddMember("blocks", block_arr, allocator);
        std::string peer_data;
        s = m_db->Get(leveldb::ReadOptions(), "peer_score", &peer_data);
        
        if(!s.ok())
        {
            CONSOLE_LOG_FATAL("read peer score data from leveldb failed: %s", s.ToString().c_str());

            return false;
        }
        
        rapidjson::Document doc_peer;
        const char *peer_data_str = peer_data.c_str();
        doc_peer.Parse(peer_data_str);
        
        if(doc_peer.HasParseError())
        {
            ASKCOIN_RETURN false;
        }
        
        if(!doc_peer.IsObject())
        {
            ASKCOIN_RETURN false;
        }
        
        if(!doc_peer.HasMember("peers"))
        {
            ASKCOIN_RETURN false;
        }

        if(!doc_peer.HasMember("utc"))
        {
            ASKCOIN_RETURN false;
        }

        if(!doc_peer["utc"].IsUint64())
        {
            ASKCOIN_RETURN false;
        }

        const rapidjson::Value &peers = doc_peer["peers"];
        
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
        }

        doc.AddMember("peer_score", doc_peer, allocator);
        doc.Accept(writer);
        CONSOLE_LOG_INFO("merge_point export block_id: %lu, block_hash: %s successfully", \
                         m_merge_point->m_export_block_id, m_merge_point->m_export_block_hash.c_str());
        return true;
    }
    
    char hash_raw[32];
    fly::base::base64_decode(m_cur_block->hash().c_str(), m_cur_block->hash().length(), hash_raw, 32);
    std::string hex_hash = fly::base::byte2hexstr(hash_raw, 32);
    CONSOLE_LOG_INFO("load block finished, zero_bits: %u, cur_block_id: %lu, cur_block_hash: %s (hex: %s)", \
                     m_cur_block->zero_bits(), m_cur_block->id(), m_cur_block->hash().c_str(), hex_hash.c_str());
    m_timer_ctl.add_timer([this]() {
            this->broadcast();
        }, 10000);

    m_timer_ctl.add_timer([this]() {
            uint64 utc_now = time(NULL);

            if(m_last_mine_time + 5 < utc_now)
            {
                mine_tx();
                m_last_mine_time = time(NULL);
            }
        }, 1000);
    
    for(auto p : m_account_by_id)
    {
        auto account = p.second;
        account->proc_history_expired(m_cur_block->id());
    }
    
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
    
    std::thread msg_thread(std::bind(&Blockchain::do_message, this));
    m_msg_thread = std::move(msg_thread);

    std::thread mine_thread(std::bind(&Blockchain::do_mine, this));
    m_mine_thread = std::move(mine_thread);
    
    std::thread score_thread(std::bind(&Blockchain::do_score, this));
    m_score_thread = std::move(score_thread);
    
    return true;
}

bool Blockchain::check_balance()
{
    uint64 total_coin = 0;
    
    for(auto p : m_account_by_id)
    {
        auto account = p.second;
        total_coin += account->get_balance();
    }
    
    for(auto topic : m_topic_list)
    {
        total_coin += topic->get_balance();
    }
    
    return total_coin == (uint64)1000000000000UL;
}

void Blockchain::mine_tx()
{
    if(!m_enable_mine.load(std::memory_order_relaxed))
    {
        return;
    }

    std::unique_lock<std::mutex> lock(m_mine_mutex);
    
    if(m_miner_privkey.empty())
    {
        return;
    }
    
    lock.unlock();
    m_mine_id_1.fetch_add(1, std::memory_order_relaxed);
    std::shared_ptr<Account> miner;
    
    if(!get_account(m_miner_pubkey, miner))
    {
        return;
    }
    
    std::list<std::shared_ptr<tx::Tx>> uv_2_txs;
    std::list<std::shared_ptr<tx::Tx>> mined_txs;
    uv_2_txs.insert(uv_2_txs.begin(), m_uv_2_txs.begin(), m_uv_2_txs.end());
    uint64 cnt = 0;
    uint64 remain_cnt = uv_2_txs.size();
    uint64 total_cnt = uv_2_txs.size();
    uint64 last_mined_cnt = 0;
    uint64 loop_cnt = 0;
    uint64 cur_block_id = m_cur_block->id() + 1;
    std::shared_ptr<Block> cur_block(new Block(cur_block_id, m_cur_block->utc(), ASKCOIN_VERSION, m_cur_block->zero_bits(), "temp_hash"));
    cur_block->set_parent(m_cur_block);
    
    if(!proc_topic_expired(cur_block_id))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    if(!proc_tx_map(cur_block))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    while(!uv_2_txs.empty())
    {
        // because tx may not be in order, so need loop 3 times to resolve dependency problem.
        if(++cnt > remain_cnt)
        {
            if(++loop_cnt >= 3)
            {
                break;
            }

            cnt = 1;
            uint64 mined_cnt = mined_txs.size();

            if(mined_cnt == last_mined_cnt)
            {
                break;
            }

            last_mined_cnt = mined_cnt;
            remain_cnt = total_cnt - mined_cnt;
        }
        
        auto tx = uv_2_txs.front();
        auto tx_type = tx->m_type;
        auto block_id = tx->m_block_id;
        auto tx_id = tx->m_id;
        auto pubkey = tx->m_pubkey;
        auto &doc = *tx->m_doc;
        const rapidjson::Value &data = doc["data"];
        
        if(m_tx_map.find(tx_id) != m_tx_map.end())
        {
            uv_2_txs.push_back(tx);
            uv_2_txs.pop_front();
            continue;
        }
        
        if(tx_type == 1)
        {
            std::shared_ptr<tx::Tx_Reg> tx_reg = std::static_pointer_cast<tx::Tx_Reg>(tx);
            auto register_name = tx_reg->m_register_name;
            std::shared_ptr<Account> exist_account;
            
            if(get_account(pubkey, exist_account))
            {
                uv_2_txs.push_back(tx);
                uv_2_txs.pop_front();
                continue;
            }
            
            if(account_name_exist(register_name))
            {
                uv_2_txs.push_back(tx);
                uv_2_txs.pop_front();
                continue;
            }
            
            std::shared_ptr<Account> referrer;
            
            if(!get_account(tx_reg->m_referrer_pubkey, referrer))
            {
                uv_2_txs.push_back(tx);
                uv_2_txs.pop_front();
                continue;
            }
            
            if(referrer->get_balance() < 2)
            {
                uv_2_txs.push_back(tx);
                uv_2_txs.pop_front();
                continue;
            }
            
            std::shared_ptr<Account> referrer_referrer = referrer->get_referrer();
                    
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
            
            referrer->sub_balance(2);
            std::shared_ptr<Account> reg_account(new Account(++m_cur_account_id, register_name, pubkey, tx_reg->m_avatar, cur_block_id));
            m_account_names.insert(register_name);
            m_account_by_pubkey.insert(std::make_pair(pubkey, reg_account));
            reg_account->set_referrer(referrer);
        }
        else
        {
            std::shared_ptr<Account> account;
            
            if(!get_account(pubkey, account))
            {
                uv_2_txs.push_back(tx);
                uv_2_txs.pop_front();
                continue;
            }
            
            if(account->get_balance() < 2)
            {
                uv_2_txs.push_back(tx);
                uv_2_txs.pop_front();
                continue;
            }
            
            std::shared_ptr<Account> referrer = account->get_referrer();
                    
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
            
            account->sub_balance(2);
            auto failed_cb = [=]() {
                account->add_balance(2);

                if(!referrer)
                {
                    m_reserve_fund_account->sub_balance(1);
                }
                else
                {
                    referrer->sub_balance(1);
                }
            };
            
            if(tx_type == 2) // send coin
            {
                std::shared_ptr<tx::Tx_Send> tx_send = std::static_pointer_cast<tx::Tx_Send>(tx);
                uint64 amount = tx_send->m_amount;

                if(account->get_balance() < amount)
                {
                    failed_cb();
                    uv_2_txs.push_back(tx);
                    uv_2_txs.pop_front();
                    continue;
                }
                
                std::shared_ptr<Account> receiver;
                
                if(!get_account(tx_send->m_receiver_pubkey, receiver))
                {
                    failed_cb();
                    uv_2_txs.push_back(tx);
                    uv_2_txs.pop_front();
                    continue;
                }
                
                account->sub_balance(amount);
                receiver->add_balance(amount);
            }
            else if(tx_type == 3) // new topic
            {
                std::shared_ptr<tx::Tx_Topic> tx_topic = std::static_pointer_cast<tx::Tx_Topic>(tx);
                uint64 reward = tx_topic->m_reward;
                
                if(account->get_balance() < reward)
                {
                    failed_cb();
                    uv_2_txs.push_back(tx);
                    uv_2_txs.pop_front();
                    continue;
                }
                
                std::shared_ptr<Topic> exist_topic;

                if(get_topic(tx_id, exist_topic))
                {
                    failed_cb();
                    uv_2_txs.push_back(tx);
                    uv_2_txs.pop_front();
                    continue;
                }

                std::string topic_data = data["topic"].GetString();
                
                if(account->m_topic_list.size() >= 100)
                {
                    failed_cb();
                    uv_2_txs.push_back(tx);
                    uv_2_txs.pop_front();
                    continue;
                }
                
                account->sub_balance(reward);
                std::shared_ptr<Topic> topic(new Topic(tx_id, topic_data, cur_block, reward));
                topic->set_owner(account);
                account->m_topic_list.push_back(topic);
                m_topic_list.push_back(topic);
                m_topics.insert(std::make_pair(tx_id, topic));
            }
            else if(tx_type == 4) // reply
            {
                std::shared_ptr<tx::Tx_Reply> tx_reply = std::static_pointer_cast<tx::Tx_Reply>(tx);
                std::shared_ptr<Topic> topic;
                
                if(!get_topic(tx_reply->m_topic_key, topic))
                {
                    failed_cb();
                    uv_2_txs.push_back(tx);
                    uv_2_txs.pop_front();
                    continue;
                }

                std::string reply_data = data["reply"].GetString();
                std::shared_ptr<Reply> reply(new Reply(tx_id, 0, cur_block, reply_data));
                reply->set_owner(account);
                
                if(topic->m_reply_list.size() >= 1000)
                {
                    failed_cb();
                    uv_2_txs.push_back(tx);
                    uv_2_txs.pop_front();
                    continue;
                }

                if(!tx_reply->m_reply_to.empty())
                {
                    std::shared_ptr<Reply> reply_to;
                    
                    if(!topic->get_reply(tx_reply->m_reply_to, reply_to))
                    {
                        failed_cb();
                        uv_2_txs.push_back(tx);
                        uv_2_txs.pop_front();
                        continue;
                    }
                    
                    if(reply_to->type() != 0)
                    {
                        failed_cb();
                        uv_2_txs.push_back(tx);
                        uv_2_txs.pop_front();
                        continue;
                    }
                    
                    reply->set_reply_to(reply_to);
                }
                
                if(topic->get_owner() != account)
                {
                    if(!account->joined_topic(topic))
                    {
                        if(account->m_joined_topic_list.size() >= 100)
                        {
                            failed_cb();
                            uv_2_txs.push_back(tx);
                            uv_2_txs.pop_front();
                            continue;
                        }
                        
                        account->m_joined_topic_list.push_back(topic);
                        topic->add_member(tx_id, account);
                    }
                }
                        
                topic->m_reply_list.push_back(reply);
            }
            else if(tx_type == 5) // reward
            {
                std::shared_ptr<tx::Tx_Reward> tx_reward = std::static_pointer_cast<tx::Tx_Reward>(tx);
                std::shared_ptr<Topic> topic;
                uint64 amount = tx_reward->m_amount;

                if(!get_topic(tx_reward->m_topic_key, topic))
                {
                    failed_cb();
                    uv_2_txs.push_back(tx);
                    uv_2_txs.pop_front();
                    continue;
                }
                
                if(topic->get_owner() != account)
                {
                    failed_cb();
                    uv_2_txs.push_back(tx);
                    uv_2_txs.pop_front();
                    continue;
                }
                
                std::shared_ptr<Reply> reply(new Reply(tx_id, 1, cur_block, ""));
                reply->set_owner(account);
                    
                if(topic->m_reply_list.size() >= 1000)
                {
                    failed_cb();
                    uv_2_txs.push_back(tx);
                    uv_2_txs.pop_front();
                    continue;
                }
                
                if(topic->get_balance() < amount)
                {
                    failed_cb();
                    uv_2_txs.push_back(tx);
                    uv_2_txs.pop_front();
                    continue;
                }

                std::shared_ptr<Reply> reply_to;
                
                if(!topic->get_reply(tx_reward->m_reply_to, reply_to))
                {
                    failed_cb();
                    uv_2_txs.push_back(tx);
                    uv_2_txs.pop_front();
                    continue;
                }
                
                if(reply_to->type() != 0)
                {
                    failed_cb();
                    uv_2_txs.push_back(tx);
                    uv_2_txs.pop_front();
                    continue;
                }
                
                if(reply_to->get_owner() == account)
                {
                    failed_cb();
                    uv_2_txs.push_back(tx);
                    uv_2_txs.pop_front();
                    continue;
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
        
        m_tx_map.insert(std::make_pair(tx_id, cur_block));
        mined_txs.push_back(tx);
        uv_2_txs.pop_front();
        
        if(mined_txs.size() >= 2000)
        {
            break;
        }
    }
    
    for(auto iter = mined_txs.rbegin(); iter != mined_txs.rend(); ++iter)
    {
        auto tx = *iter;
        auto tx_type = tx->m_type;
        auto block_id = tx->m_block_id;
        auto tx_id = tx->m_id;
        auto pubkey = tx->m_pubkey;
        auto &doc = *tx->m_doc;
        const rapidjson::Value &data = doc["data"];
        m_tx_map.erase(tx_id);

        if(tx_type == 1)
        {
            std::shared_ptr<tx::Tx_Reg> tx_reg = std::static_pointer_cast<tx::Tx_Reg>(tx);
            auto register_name = tx_reg->m_register_name;
            std::shared_ptr<Account> referrer;
            get_account(tx_reg->m_referrer_pubkey, referrer);
            std::shared_ptr<Account> referrer_referrer = referrer->get_referrer();
            
            if(!referrer_referrer)
            {
                m_reserve_fund_account->sub_balance(1);
            }
            else
            {
                referrer_referrer->sub_balance(1);
            }
            
            referrer->add_balance(2);
            m_account_names.erase(register_name);
            m_account_by_pubkey.erase(pubkey);
            --m_cur_account_id;
        }
        else
        {
            std::shared_ptr<Account> account;
            get_account(pubkey, account);
            std::shared_ptr<Account> referrer = account->get_referrer();
            
            if(!referrer)
            {
                m_reserve_fund_account->sub_balance(1);
            }
            else
            {
                referrer->sub_balance(1);
            }
            
            account->add_balance(2);
            
            if(tx_type == 2) // send coin
            {
                std::shared_ptr<tx::Tx_Send> tx_send = std::static_pointer_cast<tx::Tx_Send>(tx);
                uint64 amount = tx_send->m_amount;
                std::shared_ptr<Account> receiver;
                get_account(tx_send->m_receiver_pubkey, receiver);
                account->add_balance(amount);
                receiver->sub_balance(amount);
            }
            else if(tx_type == 3) // new topic
            {
                std::shared_ptr<tx::Tx_Topic> tx_topic = std::static_pointer_cast<tx::Tx_Topic>(tx);
                uint64 reward = tx_topic->m_reward;
                account->add_balance(reward);
                account->m_topic_list.pop_back();
                m_topic_list.pop_back();
                m_topics.erase(tx_id);
            }
            else if(tx_type == 4) // reply
            {
                std::shared_ptr<tx::Tx_Reply> tx_reply = std::static_pointer_cast<tx::Tx_Reply>(tx);
                std::shared_ptr<Topic> topic;
                get_topic(tx_reply->m_topic_key, topic);
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
                std::shared_ptr<tx::Tx_Reward> tx_reward = std::static_pointer_cast<tx::Tx_Reward>(tx);
                std::shared_ptr<Topic> topic;
                get_topic(tx_reward->m_topic_key, topic);
                std::shared_ptr<Reply> reply_to;
                topic->get_reply(tx_reward->m_reply_to, reply_to);
                uint64 amount = tx_reward->m_amount;
                topic->add_balance(amount);
                reply_to->sub_balance(amount);
                reply_to->get_owner()->sub_balance(amount);
                topic->m_reply_list.pop_back();
            }
        }
    }
    
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
    
    uint32 parent_zero_bits = m_cur_block->zero_bits();
    uint64 utc_diff = m_cur_block->utc_diff();
    uint32 zero_bits = 1;

    if(utc_diff < 10)
    {
        zero_bits = parent_zero_bits + 1;
    }
    else if(utc_diff > 30)
    {
        if(parent_zero_bits > 1)
        {
            zero_bits = parent_zero_bits - 1;
        }
        else
        {
            zero_bits = 1;
        }
    }
    else
    {
        zero_bits = parent_zero_bits;
    }

    lock.lock();
    m_mined_txs = std::move(mined_txs);
    m_mine_cur_block_id = m_cur_block->id();
    m_mine_cur_block_hash = m_cur_block->hash();
    m_mine_cur_block_utc = m_cur_block->utc();
    m_mine_zero_bits = zero_bits;
    lock.unlock();
    m_need_remine.store(true, std::memory_order_release);
}

void Blockchain::mined_new_block(std::shared_ptr<rapidjson::Document> doc_ptr)
{
    auto &doc = *doc_ptr;
    
    if(!doc.HasMember("hash"))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    if(!doc.HasMember("sign"))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(!doc["hash"].IsString())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(!doc["sign"].IsString())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    std::string block_hash = doc["hash"].GetString();
    std::string block_sign = doc["sign"].GetString();

    if(!is_base64_char(block_hash))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    if(!is_base64_char(block_sign))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(block_hash.length() != 44)
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
            
    if(m_blocks.find(block_hash) != m_blocks.end())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(!doc.HasMember("data"))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
            
    const rapidjson::Value &data = doc["data"];

    if(!data.IsObject())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    data.Accept(writer);
    std::string data_str(buffer.GetString(), buffer.GetSize());

    if(!data.HasMember("id"))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(!data["id"].IsUint64())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    uint64 block_id = data["id"].GetUint64();

    if(block_id == 0)
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(!data.HasMember("utc"))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(!data["utc"].IsUint64())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    uint64 utc = data["utc"].GetUint64();

    if(!data.HasMember("version"))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(!data["version"].IsUint())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    uint32 version = data["version"].GetUint();
    
    if(!version_compatible(version, ASKCOIN_VERSION))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    if(!data.HasMember("zero_bits"))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(!data["zero_bits"].IsUint())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    uint32 zero_bits = data["zero_bits"].GetUint();

    if(zero_bits == 0 || zero_bits >= 256)
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
            
    if(!data.HasMember("pre_hash"))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(!data["pre_hash"].IsString())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    std::string pre_hash = data["pre_hash"].GetString();

    if(!is_base64_char(pre_hash))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
            
    if(pre_hash.length() != 44)
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    if(!data.HasMember("miner"))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(!data["miner"].IsString())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    std::string miner_pubkey = data["miner"].GetString();

    if(!is_base64_char(miner_pubkey))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(miner_pubkey.length() != 88)
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(!data.HasMember("nonce"))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    const rapidjson::Value &nonce = data["nonce"];

    if(!nonce.IsArray())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(nonce.Size() != 4)
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
            
    for(uint32 i = 0; i < 4; ++i)
    {
        if(!nonce[i].IsUint64())
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
    }
    
    if(!data.HasMember("tx_ids"))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
            
    const rapidjson::Value &tx_ids = data["tx_ids"];

    if(!tx_ids.IsArray())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
            
    uint32 tx_num = tx_ids.Size();
            
    if(tx_num > 2000)
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    for(rapidjson::Value::ConstValueIterator iter = tx_ids.Begin(); iter != tx_ids.End(); ++iter)
    {
        if(!iter->IsString())
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }

        std::string tx_id = iter->GetString();
                
        if(!is_base64_char(tx_id))
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }

        if(tx_id.length() != 44)
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
    }
    
    if(!verify_sign(miner_pubkey, block_hash, block_sign))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    if(!verify_hash(block_hash, data_str, zero_bits))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    std::shared_ptr<Account> miner;
    
    if(!get_account(miner_pubkey, miner))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    uint64 parent_block_id = m_cur_block->id();
    std::string parent_hash = m_cur_block->hash();
    uint64 parent_utc = m_cur_block->utc();
    uint32 parent_zero_bits = m_cur_block->zero_bits();
    uint64 utc_diff = m_cur_block->utc_diff();
            
    if(block_id != parent_block_id + 1)
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    if(pre_hash != parent_hash)
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    if(utc_diff < 10)
    {
        if(zero_bits != parent_zero_bits + 1)
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
    }
    else if(utc_diff > 30)
    {
        if(parent_zero_bits > 1)
        {
            if(zero_bits != parent_zero_bits - 1)
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
        }
        else if(zero_bits != 1)
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
    }
    else if(zero_bits != parent_zero_bits)
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    if(utc < parent_utc)
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    uint64 now = time(NULL);
    
    if(utc > now)
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    std::shared_ptr<Block> cur_block(new Block(block_id, utc, version, zero_bits, block_hash));
    cur_block->set_parent(m_cur_block);
    cur_block->set_miner_pubkey(miner_pubkey);
    cur_block->add_difficulty_from(m_cur_block);
    cur_block->m_tx_num = tx_num;
    uint64 cur_block_id = block_id;
    
    if(!proc_topic_expired(cur_block_id))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(!proc_tx_map(cur_block))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    if(!doc.HasMember("tx"))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    const rapidjson::Value &tx = doc["tx"];
    
    if(tx_num != tx.Size())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    for(uint32 i = 0; i < tx_num; ++i)
    {
        std::string tx_id = tx_ids[i].GetString();
        const rapidjson::Value &tx_node = tx[i];
        const rapidjson::Value &data = tx_node["data"];
        std::string pubkey = data["pubkey"].GetString();
        uint32 tx_type = data["type"].GetUint();
        
        if(m_tx_map.find(tx_id) != m_tx_map.end())
        {
            ASKCOIN_EXIT(EXIT_FAILURE);
        }
        
        if(tx_type == 1)
        {
            if(!data.HasMember("avatar"))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }

            if(!data["avatar"].IsUint())
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
                    
            if(!data.HasMember("sign"))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }

            if(!data["sign"].IsString())
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

            if(!sign_data.IsObject())
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
                    
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
            sign_data.Accept(writer);
            std::string sign_hash = coin_hash_b64(buffer.GetString(), buffer.GetSize());
                
            if(!sign_data.HasMember("block_id"))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }

            if(!sign_data["block_id"].IsUint64())
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
                    
            if(!sign_data.HasMember("name"))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }

            if(!sign_data["name"].IsString())
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
                    
            if(!sign_data.HasMember("referrer"))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }

            if(!sign_data["referrer"].IsString())
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
                    
            if(!sign_data.HasMember("fee"))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }

            if(!sign_data["fee"].IsUint64())
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
            
            std::shared_ptr<Account> referrer_referrer = referrer->get_referrer();
                    
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
                auto history = std::make_shared<History>(HISTORY_REFERRER_REWARD);
                history->m_block_id = cur_block_id;
                history->m_block_hash = block_hash;
                history->m_change = 1;
                history->m_target_id = referrer->id();
                history->m_target_avatar = referrer->avatar();
                history->m_target_name = referrer->name();
                history->m_utc = utc;
                history->m_tx_id = tx_id;
                referrer_referrer->add_history(history);
            }

            referrer->sub_balance(2);
            std::shared_ptr<Account> reg_account(new Account(++m_cur_account_id, register_name, pubkey, avatar, cur_block_id));
            m_account_names.insert(register_name);
            m_account_by_pubkey.insert(std::make_pair(pubkey, reg_account));
            m_account_by_id.insert(std::make_pair(m_cur_account_id, reg_account));
            reg_account->set_referrer(referrer);
            notify_register_account(reg_account);
            auto history = std::make_shared<History>(HISTORY_REG_FEE);
            history->m_block_id = cur_block_id;
            history->m_block_hash = block_hash;
            history->m_change = 2;
            
            // history->m_target_id = reg_account->id();
            // history->m_target_avatar = reg_account->avatar();
            // history->m_target_name = reg_account->name();
            
            history->m_utc = utc;
            history->m_tx_id = tx_id;
            referrer->add_history(history);
        }
        else
        {
            if(!data.HasMember("fee"))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }

            if(!data["fee"].IsUint64())
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
                    
            if(!data.HasMember("block_id"))
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }

            if(!data["block_id"].IsUint64())
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
                auto history = std::make_shared<History>(HISTORY_REFERRER_REWARD);
                history->m_block_id = cur_block_id;
                history->m_block_hash = block_hash;
                history->m_change = 1;
                history->m_target_id = account->id();
                history->m_target_avatar = account->avatar();
                history->m_target_name = account->name();
                history->m_utc = utc;
                history->m_tx_id = tx_id;
                referrer->add_history(history);
            }
            
            account->sub_balance(2);
            auto history = std::make_shared<History>();
            history->m_block_id = cur_block_id;
            history->m_block_hash = block_hash;
            history->m_change = 2;
            history->m_utc = utc;
            history->m_tx_id = tx_id;
            account->add_history(history);
            
            if(tx_type == 2) // send coin
            {
                history->m_type = HISTORY_SEND_FEE;
                auto history_to = std::make_shared<History>(HISTORY_SEND_TO);
                auto history_from = std::make_shared<History>(HISTORY_SEND_FROM);
                
                if(data.HasMember("memo"))
                {
                    if(!data["memo"].IsString())
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    std::string memo = data["memo"].GetString();

                    if(memo.empty())
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    if(!is_base64_char(memo))
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                            
                    if(memo.length() > 80 || memo.length() < 4)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    history_from->m_memo = memo;
                    history_to->m_memo = memo;
                }
                
                if(!data.HasMember("amount"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                        
                if(!data["amount"].IsUint64())
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
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

                if(!data.HasMember("receiver"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(!data["receiver"].IsString())
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
                history_to->m_block_id = cur_block_id;
                history_to->m_block_hash = block_hash;
                history_to->m_change = amount;
                history_to->m_utc = utc;
                history_to->m_target_id = receiver->id();
                history_to->m_target_avatar = receiver->avatar();
                history_to->m_target_name = receiver->name();
                history_to->m_tx_id = tx_id;
                account->add_history(history_to);
                history_from->m_block_id = cur_block_id;
                history_from->m_block_hash = block_hash;
                history_from->m_change = amount;
                history_from->m_utc = utc;
                history_from->m_target_id = account->id();
                history_from->m_target_avatar = account->avatar();
                history_from->m_target_name = account->name();
                history_from->m_tx_id = tx_id;
                receiver->add_history(history_from);
                notify_exchange_account_deposit(receiver, history_from);
            }
            else if(tx_type == 3) // new topic
            {
                history->m_type = HISTORY_NEW_TOPIC_FEE;
                
                if(!data.HasMember("reward"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(!data["reward"].IsUint64())
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

                if(!data.HasMember("topic"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(!data["topic"].IsString())
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                        
                std::string topic_data = data["topic"].GetString();
                    
                if(!is_base64_char(topic_data))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(topic_data.length() < 4 || topic_data.length() > 1336)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                    
                if(account->m_topic_list.size() >= 100)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                account->sub_balance(reward);
                std::shared_ptr<Topic> topic(new Topic(tx_id, topic_data, cur_block, reward));
                topic->set_owner(account);
                account->m_topic_list.push_back(topic);
                m_topic_list.push_back(topic);
                m_topics.insert(std::make_pair(tx_id, topic));
                broadcast_new_topic(topic);
                auto history = std::make_shared<History>(HISTORY_NEW_TOPIC_REWARD);
                history->m_block_id = cur_block_id;
                history->m_block_hash = block_hash;
                history->m_change = reward;
                history->m_utc = utc;
                history->m_tx_id = tx_id;
                account->add_history(history);
            }
            else if(tx_type == 4) // reply
            {
                history->m_type = HISTORY_REPLY_FEE;
                
                if(!data.HasMember("topic_key"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(!data["topic_key"].IsString())
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                        
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

                if(!data.HasMember("reply"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(!data["reply"].IsString())
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                        
                std::string reply_data = data["reply"].GetString();
                    
                if(!is_base64_char(reply_data))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(reply_data.length() < 4 || reply_data.length() > 1336)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                    
                std::shared_ptr<Reply> reply(new Reply(tx_id, 0, cur_block, reply_data));
                reply->set_owner(account);
                    
                if(topic->m_reply_list.size() >= 1000)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(data.HasMember("reply_to"))
                {
                    if(!data["reply_to"].IsString())
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
                
                topic->m_reply_list.push_back(reply);
            }
            else if(tx_type == 5) // reward
            {
                history->m_type = HISTORY_REWARD_FEE;
                
                if(!data.HasMember("topic_key"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(!data["topic_key"].IsString())
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                        
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
                    
                std::shared_ptr<Reply> reply(new Reply(tx_id, 1, cur_block, ""));
                reply->set_owner(account);
                    
                if(topic->m_reply_list.size() >= 1000)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(!data.HasMember("amount"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(!data["amount"].IsUint64())
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

                if(!data.HasMember("reply_to"))
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }

                if(!data["reply_to"].IsString())
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
                
                if(reply_to->get_owner() == account)
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
                
                reply->set_reply_to(reply_to);
                topic->sub_balance(amount);
                reply_to->add_balance(amount);
                reply_to->get_owner()->add_balance(amount);
                reply->add_balance(amount);
                topic->m_reply_list.push_back(reply);
                auto history = std::make_shared<History>(HISTORY_REWARD_FROM);
                history->m_block_id = cur_block_id;
                history->m_block_hash = block_hash;
                history->m_change = amount;
                history->m_utc = utc;
                history->m_target_id = account->id();
                history->m_target_avatar = account->avatar();
                history->m_target_name = account->name();
                history->m_tx_id = tx_id;
                reply_to->get_owner()->add_history(history);
            }
            else
            {
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
        }
        
        m_tx_map.insert(std::make_pair(tx_id, cur_block));
    }
    
    uint64 remain_balance = m_reserve_fund_account->get_balance();

    if(tx_num > 0)
    {
        miner->add_balance(tx_num);
        auto history = std::make_shared<History>(HISTORY_MINER_TX_REWARD);
        history->m_block_id = cur_block_id;
        history->m_block_hash = block_hash;
        history->m_change = tx_num;
        history->m_utc = utc;
        miner->add_history(history);
    }

    if(remain_balance >= 5000)
    {
        m_reserve_fund_account->sub_balance(5000);
        miner->add_balance(5000);
        cur_block->m_miner_reward = true;
        auto history = std::make_shared<History>(HISTORY_MINER_BLOCK_REWARD);
        history->m_block_id = cur_block_id;
        history->m_block_hash = block_hash;
        history->m_change = 5000;
        history->m_utc = utc;
        miner->add_history(history);
    }
    else
    {
        cur_block->m_miner_reward = false;
    }

    m_miner_pubkeys.insert(miner_pubkey);
    std::string block_data;
    leveldb::Status s;

    if(block_id == 1)
    {
        s = m_db->Get(leveldb::ReadOptions(), "0", &block_data);
    }
    else
    {
        s = m_db->Get(leveldb::ReadOptions(), pre_hash, &block_data);
    }
    
    if(!s.ok())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    rapidjson::Document doc_parent;
    const char *block_data_str = block_data.c_str();
    doc_parent.Parse(block_data_str);
            
    if(doc_parent.HasParseError())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(!doc_parent.IsObject())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    if(!doc_parent.HasMember("children"))
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
            
    rapidjson::Value &children = doc_parent["children"];

    if(!children.IsArray())
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }
    
    bool exist_in_children = false;
    bool exist_block_hash = true;
    
    for(rapidjson::Value::ConstValueIterator iter = children.Begin(); iter != children.End(); ++iter)
    {
        if(block_hash == iter->GetString())
        {
            exist_in_children = true;
            LOG_DEBUG_INFO("exist_in_children = true, block_hash: %s, pre_hash: %s", block_hash.c_str(), pre_hash.c_str());
            break;
        }
    }
            
    {
        std::string block_data;
        leveldb::Status s = m_db->Get(leveldb::ReadOptions(), block_hash, &block_data);
            
        if(!s.ok())
        {
            if(!s.IsNotFound())
            {
                CONSOLE_LOG_FATAL("read from leveldb failed, hash: %s, reason: %s", block_hash.c_str(), s.ToString().c_str());
                ASKCOIN_EXIT(EXIT_FAILURE);
            }
                    
            exist_block_hash = false;
        }
    }
            
    if(exist_in_children || exist_block_hash)
    {
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    rapidjson::Value children_arr(rapidjson::kArrayType);
    doc.AddMember("children", children_arr, doc.GetAllocator());
    rapidjson::StringBuffer buffer_1;
    rapidjson::Writer<rapidjson::StringBuffer> writer_1(buffer_1);
    doc.Accept(writer_1);
    leveldb::WriteBatch batch;
    batch.Put(block_hash, leveldb::Slice(buffer_1.GetString(), buffer_1.GetSize()));
    children.PushBack(rapidjson::StringRef(block_hash.c_str()), doc_parent.GetAllocator());
    rapidjson::StringBuffer buffer_2;
    rapidjson::Writer<rapidjson::StringBuffer> writer_2(buffer_2);
    doc_parent.Accept(writer_2);
    
    if(block_id == 1)
    {
        batch.Put("0", leveldb::Slice(buffer_2.GetString(), buffer_2.GetSize()));
    }
    else
    {
        batch.Put(pre_hash, leveldb::Slice(buffer_2.GetString(), buffer_2.GetSize()));
    }
    
    char hash_raw[32];
    fly::base::base64_decode(block_hash.c_str(), block_hash.length(), hash_raw, 32);
    std::string hex_hash = fly::base::byte2hexstr(hash_raw, 32);
    LOG_DEBUG_INFO("mined_new_block, zero_bits: %u, block_id: %lu, block_hash: %s (hex: %s), start write to leveldb", \
                   zero_bits, block_id, block_hash.c_str(), hex_hash.c_str());
    s = m_db->Write(leveldb::WriteOptions(), &batch);
    
    if(!s.ok())
    {
        LOG_FATAL("writebatch failed, block_hash: %s, pre_hash: %s", block_hash.c_str(), pre_hash.c_str());
        ASKCOIN_EXIT(EXIT_FAILURE);
    }

    LOG_INFO("mined_new_block, zero_bits: %u, block_id: %lu, block_hash: %s (hex: %s), write to leveldb completely", \
             zero_bits, block_id, block_hash.c_str(), hex_hash.c_str());
    m_blocks.insert(std::make_pair(block_hash, cur_block));
    m_block_by_id.insert(std::make_pair(block_id, cur_block));
    m_cur_block = cur_block;
    m_cur_block->m_in_main_chain = true;
    
    if(m_most_difficult_block->difficult_than_me(m_cur_block))
    {
        m_most_difficult_block = m_cur_block;
        m_broadcast_doc = doc_ptr;
        broadcast();
    }
    
    m_block_changed = true;
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

            if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 1 + 100)
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
            if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 1 + 100)
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
                
                uint64 topic_block_id = topic->m_block->id();

                if(topic_block_id + TOPIC_LIFE_TIME < cur_block_id + 1)
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

                uint64 topic_block_id = topic->m_block->id();
                
                if(topic_block_id + TOPIC_LIFE_TIME < cur_block_id + 1)
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
                
                if(reply_to->get_owner() == account)
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
            
            if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 1 + 100)
            {
                iter = m_uv_2_txs.erase(iter);
                m_uv_tx_ids.erase(tx_id);
                m_uv_account_names.erase(register_name);
                m_uv_account_pubkeys.erase(pubkey);
                notify_register_failed(pubkey, 2);
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
                notify_register_failed(pubkey, 1);
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
            
            if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 1 + 100)
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

            if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 1 + 100)
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
                uint64 topic_block_id = topic_outer->m_block->id();

                if(topic_block_id + TOPIC_LIFE_TIME < cur_block_id + 1)
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
            
            if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 1 + 100)
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
                uint64 topic_block_id = topic_outer->m_block->id();
                
                if(topic_block_id + TOPIC_LIFE_TIME < cur_block_id + 1)
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
            
            if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 1 + 100)
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

    for(auto iter = m_uv_3_txs.begin(); iter != m_uv_3_txs.end();)
    {
        auto tx = *iter;
        auto block_id = tx->m_block_id;
        auto tx_id = tx->m_id;

        if(block_id + 100 < cur_block_id + 1 || block_id > cur_block_id + 1 + 100)
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
    
    mine_tx();
}

void Blockchain::dispatch_peer_message(std::unique_ptr<fly::net::Message<Json>> message)
{
    m_peer_messages.push(std::move(message));
}

void Blockchain::dispatch_wsock_message(std::unique_ptr<fly::net::Message<Wsock>> message)
{
    m_wsock_messages.push(std::move(message));
}

void Blockchain::push_command(std::shared_ptr<Command> cmd)
{
    m_commands.push(cmd);
}

void Blockchain::switch_to_most_difficult()
{
    std::shared_ptr<Block> iter_block = m_cur_block;
    uint64 id = m_cur_block->id();
    uint64 id_dst = m_most_difficult_block->id();
    std::string iter_hash = m_most_difficult_block->hash();
    std::shared_ptr<Block> iter_block_1 = m_most_difficult_block;
    uint64 cross_id = 0;
    std::string cross_hash;
    std::list<std::shared_ptr<Block>> db_blocks;
    db_blocks.push_front(iter_block_1);
    LOG_INFO("switch_to_most_difficult, cur_block(id: %lu, hash: %s) dst_block(id: %lu, hash: %s)", id, \
             m_cur_block->hash().c_str(), id_dst, iter_hash.c_str());
    
    if(id == id_dst)
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
            
            iter_block = iter_block->get_parent();
            iter_block_1 = iter_block_1->get_parent();
            iter_hash = iter_block_1->hash();
            db_blocks.push_front(iter_block_1);
        }
    }
    else
    {
        if(id < id_dst)
        {
            while(id < id_dst)
            {
                iter_block_1 = iter_block_1->get_parent();
                iter_hash = iter_block_1->hash();
                db_blocks.push_front(iter_block_1);
                id_dst = iter_block_1->id();
            }
        }
        else
        {
            while(id > id_dst)
            {
                iter_block = iter_block->get_parent();
                id  = iter_block->id();
            }
        }
        
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
            
            iter_block_1 = iter_block_1->get_parent();
            iter_hash = iter_block_1->hash();
            db_blocks.push_front(iter_block_1);
            iter_block = iter_block->get_parent();
        }
    }
    
    uint64 cur_id  = m_cur_block->id();
    
    if(cross_id < cur_id)
    {
        uint64 distance = cur_id - cross_id;
        LOG_INFO("switch_to_most_difficult, rollback distance: %lu", distance);
        
        if(distance > 50)
        {
            LOG_WARN("switch_to_most_difficult, rollback distance too long, distance: %lu", distance);
        }
        
        rollback(cross_id);
        m_block_changed = true;
    }

    for(auto iter_block : db_blocks)
    {
        m_cur_block = iter_block;
        m_cur_block->m_in_main_chain = true;
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
            LOG_FATAL("switch_to_most_difficult, leveldb read failed, block_id: %lu, block_hash: %s, reason: %s", \
                      cur_block_id, block_hash.c_str(), s.ToString().c_str());
            ASKCOIN_EXIT(EXIT_FAILURE);
        }

        rapidjson::Document doc;
        const char *block_data_str = block_data.c_str();
        doc.Parse(block_data_str);
        
        if(doc.HasParseError())
        {
            LOG_FATAL("switch_to_most_difficult, parse block data failed, block_id: %lu, block_hash: %s, reason: %s", \
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

        uint64 utc = iter_block->utc();
        
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
                    auto history = std::make_shared<History>(HISTORY_REFERRER_REWARD);
                    history->m_block_id = cur_block_id;
                    history->m_block_hash = block_hash;
                    history->m_change = 1;
                    history->m_target_id = referrer->id();
                    history->m_target_avatar = referrer->avatar();
                    history->m_target_name = referrer->name();
                    history->m_utc = utc;
                    history->m_tx_id = tx_id;
                    referrer_referrer->add_history(history);
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
                
                std::shared_ptr<Account> reg_account(new Account(++m_cur_account_id, register_name, pubkey, avatar, cur_block_id));
                m_account_names.insert(register_name);
                m_account_by_pubkey.insert(std::make_pair(pubkey, reg_account));
                m_account_by_id.insert(std::make_pair(m_cur_account_id, reg_account));
                reg_account->set_referrer(referrer);
                notify_register_account(reg_account);
                auto history = std::make_shared<History>(HISTORY_REG_FEE);
                history->m_block_id = cur_block_id;
                history->m_block_hash = block_hash;
                history->m_change = 2;
                
                // history->m_target_id = reg_account->id();
                // history->m_target_avatar = reg_account->avatar();
                // history->m_target_name = reg_account->name();
                
                history->m_utc = utc;
                history->m_tx_id = tx_id;
                referrer->add_history(history);
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
                    auto history = std::make_shared<History>(HISTORY_REFERRER_REWARD);
                    history->m_block_id = cur_block_id;
                    history->m_block_hash = block_hash;
                    history->m_change = 1;
                    history->m_target_id = account->id();
                    history->m_target_avatar = account->avatar();
                    history->m_target_name = account->name();
                    history->m_utc = utc;
                    history->m_tx_id = tx_id;
                    referrer->add_history(history);
                }

                auto history = std::make_shared<History>();
                history->m_block_id = cur_block_id;
                history->m_block_hash = block_hash;
                history->m_change = 2;
                history->m_utc = utc;
                history->m_tx_id = tx_id;
                account->add_history(history);
                
                if(tx_type == 2) // send coin
                {
                    history->m_type = HISTORY_SEND_FEE;
                    auto history_to = std::make_shared<History>(HISTORY_SEND_TO);
                    auto history_from = std::make_shared<History>(HISTORY_SEND_FROM);

                    if(data.HasMember("memo"))
                    {
                        if(!data["memo"].IsString())
                        {
                            ASKCOIN_EXIT(EXIT_FAILURE);
                        }
                        
                        std::string memo = data["memo"].GetString();
                        
                        if(memo.empty())
                        {
                            ASKCOIN_EXIT(EXIT_FAILURE);
                        }
                        
                        if(!is_base64_char(memo))
                        {
                            ASKCOIN_EXIT(EXIT_FAILURE);
                        }
                        
                        if(memo.length() > 80 || memo.length() < 4)
                        {
                            ASKCOIN_EXIT(EXIT_FAILURE);
                        }

                        history_from->m_memo = memo;
                        history_to->m_memo = memo;
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
                    history_to->m_block_id = cur_block_id;
                    history_to->m_block_hash = block_hash;
                    history_to->m_change = amount;
                    history_to->m_utc = utc;
                    history_to->m_target_id = receiver->id();
                    history_to->m_target_avatar = receiver->avatar();
                    history_to->m_target_name = receiver->name();
                    history_to->m_tx_id = tx_id;
                    account->add_history(history_to);
                    history_from->m_block_id = cur_block_id;
                    history_from->m_block_hash = block_hash;
                    history_from->m_change = amount;
                    history_from->m_utc = utc;
                    history_from->m_target_id = account->id();
                    history_from->m_target_avatar = account->avatar();
                    history_from->m_target_name = account->name();
                    history_from->m_tx_id = tx_id;
                    receiver->add_history(history_from);
                    notify_exchange_account_deposit(receiver, history_from);
                }
                else if(tx_type == 3) // new topic
                {
                    history->m_type = HISTORY_NEW_TOPIC_FEE;
                    
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

                    if(topic_data.length() < 4 || topic_data.length() > 1336)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    if(account->m_topic_list.size() >= 100)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    account->sub_balance(reward);
                    std::shared_ptr<Topic> topic(new Topic(tx_id, topic_data, iter_block, reward));
                    topic->set_owner(account);
                    account->m_topic_list.push_back(topic);
                    m_topic_list.push_back(topic);
                    m_topics.insert(std::make_pair(tx_id, topic));
                    broadcast_new_topic(topic);
                    auto history = std::make_shared<History>(HISTORY_NEW_TOPIC_REWARD);
                    history->m_block_id = cur_block_id;
                    history->m_block_hash = block_hash;
                    history->m_change = reward;
                    history->m_utc = utc;
                    history->m_tx_id = tx_id;
                    account->add_history(history);
                }
                else if(tx_type == 4) // reply
                {
                    history->m_type = HISTORY_REPLY_FEE;
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

                    if(reply_data.length() < 4 || reply_data.length() > 1336)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    std::shared_ptr<Reply> reply(new Reply(tx_id, 0, iter_block, reply_data));
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
                    history->m_type = HISTORY_REWARD_FEE;
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
                    
                    std::shared_ptr<Reply> reply(new Reply(tx_id, 1, iter_block, ""));
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

                    if(reply_to->get_owner() == account)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    reply->set_reply_to(reply_to);
                    topic->sub_balance(amount);
                    reply_to->add_balance(amount);
                    reply_to->get_owner()->add_balance(amount);
                    reply->add_balance(amount);
                    topic->m_reply_list.push_back(reply);
                    auto history = std::make_shared<History>(HISTORY_REWARD_FROM);
                    history->m_block_id = cur_block_id;
                    history->m_block_hash = block_hash;
                    history->m_change = amount;
                    history->m_utc = utc;
                    history->m_target_id = account->id();
                    history->m_target_avatar = account->avatar();
                    history->m_target_name = account->name();
                    history->m_tx_id = tx_id;
                    reply_to->get_owner()->add_history(history);
                }
                else
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
            }
            
            m_tx_map.insert(std::make_pair(tx_id, iter_block));
        }

        uint64 remain_balance = m_reserve_fund_account->get_balance();

        if(tx_num > 0)
        {
            miner->add_balance(tx_num);
            auto history = std::make_shared<History>(HISTORY_MINER_TX_REWARD);
            history->m_block_id = cur_block_id;
            history->m_block_hash = block_hash;
            history->m_change = tx_num;
            history->m_utc = utc;
            miner->add_history(history);
        }

        if(remain_balance >= 5000)
        {
            m_reserve_fund_account->sub_balance(5000);
            miner->add_balance(5000);
            iter_block->m_miner_reward = true;
            auto history = std::make_shared<History>(HISTORY_MINER_BLOCK_REWARD);
            history->m_block_id = cur_block_id;
            history->m_block_hash = block_hash;
            history->m_change = 5000;
            history->m_utc = utc;
            miner->add_history(history);
        }
        else
        {
            iter_block->m_miner_reward = false;
        }

        m_miner_pubkeys.insert(miner->pubkey());
        m_block_changed = true;
        m_block_by_id.insert(std::make_pair(cur_block_id, iter_block));
    }
}

uint64 Blockchain::switch_chain(std::shared_ptr<Pending_Detail_Request> request)
{
    auto pending_chain = *request->m_chains.begin();
    auto peer = pending_chain->m_peer;
    std::shared_ptr<Block> iter_block = m_cur_block;
    uint64 id = m_cur_block->id();
    uint64 pending_start = pending_chain->m_start;
    auto pending_block = pending_chain->m_req_blocks[pending_start];
    auto first_pending_block = pending_chain->m_req_blocks[0];
    uint64 id_pending = pending_block->m_id;
    std::string iter_hash = pending_block->m_hash;
    std::shared_ptr<Block> iter_block_1;
    uint64 cross_id = 0;
    std::string cross_hash;
    std::list<std::shared_ptr<Block>> db_blocks;
    
    LOG_INFO("switch chain, cur_block(id: %lu, hash: %s) pending_block(id: %lu, hash: %s, pre_hash: %s) from peer: %s", \
             id, m_cur_block->hash().c_str(), id_pending, iter_hash.c_str(), pending_block->m_pre_hash.c_str(), peer->key().c_str());
    
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
            
            if(pending_start > 0)
            {
                --pending_start;
                iter_hash = pending_chain->m_req_blocks[pending_start]->m_hash;
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
            
            iter_block = iter_block->get_parent();
        }
    }
    else
    {
        if(id < id_pending)
        {
            while(id < id_pending)
            {
                if(pending_start > 0)
                {
                    --pending_start;
                    iter_hash = pending_chain->m_req_blocks[pending_start]->m_hash;
                    id_pending = pending_chain->m_req_blocks[pending_start]->m_id;
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
                    id_pending = iter_block_1->id();
                }
            }
        }
        else
        {
            while(id > id_pending)
            {
                iter_block = iter_block->get_parent();
                id  = iter_block->id();
            }
        }
        
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
            
            if(pending_start > 0)
            {
                --pending_start;
                iter_hash = pending_chain->m_req_blocks[pending_start]->m_hash;
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
            
            iter_block = iter_block->get_parent();
        }
    }

    uint64 cur_id  = m_cur_block->id();
    
    if(cross_id < cur_id)
    {
        uint64 distance = cur_id - cross_id;
        LOG_INFO("switch chain, rollback distance: %lu, from peer: %s", distance, peer->key().c_str());
        
        if(distance > 50)
        {
            LOG_WARN("switch chain, rollback distance too long, distance: %lu, from peer: %s", distance, peer->key().c_str());
        }
        
        rollback(cross_id);
        m_block_changed = true;
    }

    if(cross_id >= first_pending_block->m_id)
    {
        pending_start = cross_id + 1 - first_pending_block->m_id;
    }
    else
    {
        pending_start = 0;
    }
    
    for(auto i = pending_start; i <= pending_chain->m_start; ++i)
    {
        auto iter = m_blocks.find(pending_chain->m_req_blocks[i]->m_hash);
        
        if(iter == m_blocks.end())
        {
            pending_start = i;
            break;
        }

        db_blocks.push_back(iter->second);
    }
    
    for(auto iter_block : db_blocks)
    {
        m_cur_block = iter_block;
        m_cur_block->m_in_main_chain = true;
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

        uint64 utc = iter_block->utc();
        
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
                    auto history = std::make_shared<History>(HISTORY_REFERRER_REWARD);
                    history->m_block_id = cur_block_id;
                    history->m_block_hash = block_hash;
                    history->m_change = 1;
                    history->m_target_id = referrer->id();
                    history->m_target_avatar = referrer->avatar();
                    history->m_target_name = referrer->name();
                    history->m_utc = utc;
                    history->m_tx_id = tx_id;
                    referrer_referrer->add_history(history);
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
                
                std::shared_ptr<Account> reg_account(new Account(++m_cur_account_id, register_name, pubkey, avatar, cur_block_id));
                m_account_names.insert(register_name);
                m_account_by_pubkey.insert(std::make_pair(pubkey, reg_account));
                m_account_by_id.insert(std::make_pair(m_cur_account_id, reg_account));
                reg_account->set_referrer(referrer);
                notify_register_account(reg_account);
                auto history = std::make_shared<History>(HISTORY_REG_FEE);
                history->m_block_id = cur_block_id;
                history->m_block_hash = block_hash;
                history->m_change = 2;
                
                // history->m_target_id = reg_account->id();
                // history->m_target_avatar = reg_account->avatar();
                // history->m_target_name = reg_account->name();
                
                history->m_utc = utc;
                history->m_tx_id = tx_id;
                referrer->add_history(history);
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
                    auto history = std::make_shared<History>(HISTORY_REFERRER_REWARD);
                    history->m_block_id = cur_block_id;
                    history->m_block_hash = block_hash;
                    history->m_change = 1;
                    history->m_target_id = account->id();
                    history->m_target_avatar = account->avatar();
                    history->m_target_name = account->name();
                    history->m_utc = utc;
                    history->m_tx_id = tx_id;
                    referrer->add_history(history);
                }

                auto history = std::make_shared<History>();
                history->m_block_id = cur_block_id;
                history->m_block_hash = block_hash;
                history->m_change = 2;
                history->m_utc = utc;
                history->m_tx_id = tx_id;
                account->add_history(history);
                
                if(tx_type == 2) // send coin
                {
                    history->m_type = HISTORY_SEND_FEE;
                    auto history_to = std::make_shared<History>(HISTORY_SEND_TO);
                    auto history_from = std::make_shared<History>(HISTORY_SEND_FROM);
                    
                    if(data.HasMember("memo"))
                    {
                        if(!data["memo"].IsString())
                        {
                            ASKCOIN_EXIT(EXIT_FAILURE);
                        }
                        
                        std::string memo = data["memo"].GetString();
                        
                        if(memo.empty())
                        {
                            ASKCOIN_EXIT(EXIT_FAILURE);
                        }
                        
                        if(!is_base64_char(memo))
                        {
                            ASKCOIN_EXIT(EXIT_FAILURE);
                        }
                        
                        if(memo.length() > 80 || memo.length() < 4)
                        {
                            ASKCOIN_EXIT(EXIT_FAILURE);
                        }

                        history_from->m_memo = memo;
                        history_to->m_memo = memo;
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
                    history_to->m_block_id = cur_block_id;
                    history_to->m_block_hash = block_hash;
                    history_to->m_change = amount;
                    history_to->m_utc = utc;
                    history_to->m_target_id = receiver->id();
                    history_to->m_target_avatar = receiver->avatar();
                    history_to->m_target_name = receiver->name();
                    history_to->m_tx_id = tx_id;
                    account->add_history(history_to);
                    history_from->m_block_id = cur_block_id;
                    history_from->m_block_hash = block_hash;
                    history_from->m_change = amount;
                    history_from->m_utc = utc;
                    history_from->m_target_id = account->id();
                    history_from->m_target_avatar = account->avatar();
                    history_from->m_target_name = account->name();
                    history_from->m_tx_id = tx_id;
                    receiver->add_history(history_from);
                    notify_exchange_account_deposit(receiver, history_from);
                }
                else if(tx_type == 3) // new topic
                {
                    history->m_type = HISTORY_NEW_TOPIC_FEE;

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

                    if(topic_data.length() < 4 || topic_data.length() > 1336)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    if(account->m_topic_list.size() >= 100)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    account->sub_balance(reward);
                    std::shared_ptr<Topic> topic(new Topic(tx_id, topic_data, iter_block, reward));
                    topic->set_owner(account);
                    account->m_topic_list.push_back(topic);
                    m_topic_list.push_back(topic);
                    m_topics.insert(std::make_pair(tx_id, topic));
                    broadcast_new_topic(topic);
                    auto history = std::make_shared<History>(HISTORY_NEW_TOPIC_REWARD);
                    history->m_block_id = cur_block_id;
                    history->m_block_hash = block_hash;
                    history->m_change = reward;
                    history->m_utc = utc;
                    history->m_tx_id = tx_id;
                    account->add_history(history);
                }
                else if(tx_type == 4) // reply
                {
                    history->m_type = HISTORY_REPLY_FEE;
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

                    if(reply_data.length() < 4 || reply_data.length() > 1336)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }
                    
                    std::shared_ptr<Reply> reply(new Reply(tx_id, 0, iter_block, reply_data));
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
                    history->m_type = HISTORY_REWARD_FEE;
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
                    
                    std::shared_ptr<Reply> reply(new Reply(tx_id, 1, iter_block, ""));
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

                    if(reply_to->get_owner() == account)
                    {
                        ASKCOIN_EXIT(EXIT_FAILURE);
                    }

                    reply->set_reply_to(reply_to);
                    topic->sub_balance(amount);
                    reply_to->add_balance(amount);
                    reply_to->get_owner()->add_balance(amount);
                    reply->add_balance(amount);
                    topic->m_reply_list.push_back(reply);
                    auto history = std::make_shared<History>(HISTORY_REWARD_FROM);
                    history->m_block_id = cur_block_id;
                    history->m_block_hash = block_hash;
                    history->m_change = amount;
                    history->m_utc = utc;
                    history->m_target_id = account->id();
                    history->m_target_avatar = account->avatar();
                    history->m_target_name = account->name();
                    history->m_tx_id = tx_id;
                    reply_to->get_owner()->add_history(history);
                }
                else
                {
                    ASKCOIN_EXIT(EXIT_FAILURE);
                }
            }
            
            m_tx_map.insert(std::make_pair(tx_id, iter_block));
        }

        uint64 remain_balance = m_reserve_fund_account->get_balance();

        if(tx_num > 0)
        {
            miner->add_balance(tx_num);
            auto history = std::make_shared<History>(HISTORY_MINER_TX_REWARD);
            history->m_block_id = cur_block_id;
            history->m_block_hash = block_hash;
            history->m_change = tx_num;
            history->m_utc = utc;
            miner->add_history(history);
        }
        
        if(remain_balance >= 5000)
        {
            m_reserve_fund_account->sub_balance(5000);
            miner->add_balance(5000);
            iter_block->m_miner_reward = true;
            auto history = std::make_shared<History>(HISTORY_MINER_BLOCK_REWARD);
            history->m_block_id = cur_block_id;
            history->m_block_hash = block_hash;
            history->m_change = 5000;
            history->m_utc = utc;
            miner->add_history(history);
        }
        else
        {
            iter_block->m_miner_reward = false;
        }

        m_miner_pubkeys.insert(miner->pubkey());
        m_block_changed = true;
        m_block_by_id.insert(std::make_pair(cur_block_id, iter_block));
    }
    
    return pending_start;
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

        LOG_INFO("rollback 1, id: %lu, hash: %s", cur_block_id, block_hash.c_str());
        
        if(m_cur_block->m_miner_reward)
        {
            m_reserve_fund_account->add_balance(5000);
            miner->sub_balance(5000);
            miner->pop_history();
        }
        
        if(tx_num <= 0)
        {
            ASKCOIN_TRACE;
            goto proc_tx_end;
        }
        
        miner->sub_balance(tx_num);
        miner->pop_history();
        
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
                referrer->pop_history();
                referrer->pop_history_for_explorer();
                
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
                    referrer_referrer->pop_history();
                }
                
                m_account_names.erase(register_name);
                m_account_by_pubkey.erase(pubkey);
                m_account_by_id.erase(m_cur_account_id);
                --m_cur_account_id;
            }
            else
            {
                std::shared_ptr<Account> account;
                get_account(pubkey, account);
                std::shared_ptr<Account> referrer = account->get_referrer();
                account->add_balance(2);
                account->pop_history();
                account->pop_history_for_explorer();
                
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
                    referrer->pop_history();
                }
                
                if(tx_type == 2) // send coin
                {
                    uint64 amount = data["amount"].GetUint64();
                    std::string receiver_pubkey = data["receiver"].GetString();
                    std::shared_ptr<Account> receiver;
                    get_account(receiver_pubkey, receiver);
                    account->add_balance(amount);
                    receiver->sub_balance(amount);
                    account->pop_history();
                    account->pop_history_for_explorer();
                    receiver->pop_history();
                    receiver->pop_history_for_explorer();
                }
                else if(tx_type == 3) // new topic
                {
                    uint64 reward = data["reward"].GetUint64();
                    account->add_balance(reward);
                    account->m_topic_list.pop_back();
                    m_topic_list.pop_back();
                    m_topics.erase(tx_id);
                    account->pop_history();
                    account->pop_history_for_explorer();
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
                    reply_to->get_owner()->pop_history();
                    reply_to->get_owner()->pop_history_for_explorer();
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

        m_cur_block->m_in_main_chain = false;
        m_block_by_id.erase(cur_block_id);
        m_cur_block = m_cur_block->get_parent();
        cur_block_id  = m_cur_block->id();
    }

    while(cur_block_id > block_id)
    {
        uint64 target_block_id = block_id;
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
                    
                    if(++count > TOPIC_LIFE_TIME + TOPIC_LIFE_TIME)
                    {
                        target_block_id = cur_block_id - TOPIC_LIFE_TIME - 1;
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
                        std::shared_ptr<Topic> topic(new Topic(tx_id, topic_data, iter_block, reward));
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
                        std::shared_ptr<Reply> reply(new Reply(tx_id, 0, iter_block, reply_data));
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
                        std::shared_ptr<Reply> reply(new Reply(tx_id, 1, iter_block, ""));
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
                        std::shared_ptr<Reply> reply(new Reply(tx_id, 0, iter_block, reply_data));
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
                        std::shared_ptr<Reply> reply(new Reply(tx_id, 1, iter_block, ""));
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
        
        while(cur_block_id > target_block_id)
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

            LOG_INFO("rollback 2, id: %lu, hash: %s", cur_block_id, block_hash.c_str());
            
            if(m_cur_block->m_miner_reward)
            {
                m_reserve_fund_account->add_balance(5000);
                miner->sub_balance(5000);
                miner->pop_history();
            }
            
            if(tx_num <= 0)
            {
                ASKCOIN_TRACE;
                goto proc_tx_end_1;
            }

            miner->sub_balance(tx_num);
            miner->pop_history();
            
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
                    referrer->pop_history();
                    referrer->pop_history_for_explorer();
                
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
                        referrer_referrer->pop_history();
                    }
                
                    m_account_names.erase(register_name);
                    m_account_by_pubkey.erase(pubkey);
                    m_account_by_id.erase(m_cur_account_id);
                    --m_cur_account_id;
                }
                else
                {
                    std::shared_ptr<Account> account;
                    get_account(pubkey, account);
                    std::shared_ptr<Account> referrer = account->get_referrer();
                    account->add_balance(2);
                    account->pop_history();
                    account->pop_history_for_explorer();
                
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
                        referrer->pop_history();
                    }
                
                    if(tx_type == 2) // send coin
                    {
                        uint64 amount = data["amount"].GetUint64();
                        std::string receiver_pubkey = data["receiver"].GetString();
                        std::shared_ptr<Account> receiver;
                        get_account(receiver_pubkey, receiver);
                        account->add_balance(amount);
                        receiver->sub_balance(amount);
                        account->pop_history();
                        account->pop_history_for_explorer();
                        receiver->pop_history();
                        receiver->pop_history_for_explorer();
                    }
                    else if(tx_type == 3) // new topic
                    {
                        uint64 reward = data["reward"].GetUint64();
                        account->add_balance(reward);
                        account->m_topic_list.pop_back();
                        m_topic_list.pop_back();
                        m_topics.erase(tx_id);
                        account->pop_history();
                        account->pop_history_for_explorer();
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
                        reply_to->get_owner()->pop_history();
                        reply_to->get_owner()->pop_history_for_explorer();
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

            m_cur_block->m_in_main_chain = false;
            m_block_by_id.erase(cur_block_id);
            m_cur_block = m_cur_block->get_parent();
            cur_block_id  = m_cur_block->id();
        }
    }
}
