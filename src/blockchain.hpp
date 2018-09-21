#ifndef BLOCKCHAIN
#define BLOCKCHAIN

#include <string>
#include <memory>
#include <map>
#include <set>
#include <unordered_set>
#include <unordered_map>
#include <thread>
#include "leveldb/db.h"
#include "fly/base/singleton.hpp"
#include "fly/base/lock_queue.hpp"
#include "fly/net/message.hpp"
#include "block.hpp"
#include "account.hpp"
#include "pending_brief_request.hpp"
#include "pending_detail_request.hpp"
#include "timer.hpp"
#include "tx/tx.hpp"

using fly::net::Json;
using fly::net::Wsock;

#define ASKCOIN_EXIT(code) \
    LOG_FATAL("exit(%s) at function: %s", #code, __FUNCTION__); \
    exit(code)

#define ASKCOIN_RETURN \
    LOG_DEBUG_INFO("return at function: %s", __FUNCTION__); \
    return

#define ASKCOIN_TRACE LOG_DEBUG_INFO("trace at function: %s", __FUNCTION__)
const uint32 TOPIC_LIFE_TIME = 4320;

namespace net {
namespace p2p {

class Peer;

}
}

class Blockchain : public fly::base::Singleton<Blockchain>
{
public:    
    Blockchain();
    ~Blockchain();
    bool start(std::string db_path);
    bool get_account(std::string pubkey, std::shared_ptr<Account> &account);
    std::string sign(std::string privk_b64, std::string hash_b64);
    bool verify_sign(std::string pubk_b64, std::string hash_b64, std::string sign_b64);
    bool verify_hash(std::string block_hash, std::string block_data, uint32 zero_bits);
    bool hash_pow(char hash_arr[32], uint32 zero_bits);
    bool is_base64_char(std::string b64);
    bool account_name_exist(std::string name);
    bool get_topic(std::string key, std::shared_ptr<Topic> &topic);
    bool proc_topic_expired(uint64 cur_block_id);
    bool proc_tx_map(std::shared_ptr<Block> block);
    void del_account_rich(std::shared_ptr<Account> account);
    void add_account_rich(std::shared_ptr<Account> account);
    void dispatch_peer_message(std::unique_ptr<fly::net::Message<Json>> message);
    void dispatch_wsock_message(std::unique_ptr<fly::net::Message<Wsock>> message);
    void do_message();
    void do_score();
    void stop();
    void broadcast();
    void wait();
    
private:
    void do_peer_message(std::unique_ptr<fly::net::Message<Json>> &message);
    void punish_peer(std::shared_ptr<net::p2p::Peer> peer);
    void punish_brief_req(std::shared_ptr<Pending_Brief_Request> req);
    void punish_detail_req(std::shared_ptr<Pending_Detail_Request> request);
    void do_wsock_message(std::unique_ptr<fly::net::Message<Wsock>> &message);
    void do_brief_chain();
    void do_uv_tx();
    
private:
    void switch_chain(std::shared_ptr<Pending_Chain> pending_chain);
    void rollback(uint64 block_id);
    std::atomic<bool> m_stop{false};
    std::thread m_msg_thread;
    std::thread m_score_thread;
    bool check_balance();
    uint64 m_cur_account_id = 0;
    leveldb::DB *m_db;
    bool m_new_block_msg = false;
    std::shared_ptr<Block> m_cur_block;
    std::shared_ptr<Block> m_most_difficult_block;
    std::multiset<std::shared_ptr<Account>, Account::Rich_Comp> m_account_by_rich;
    std::unordered_set<std::string> m_account_names;
    std::unordered_set<std::string> m_uv_account_names; //unverified acc names
    std::unordered_map<std::string, std::shared_ptr<Account>> m_account_by_pubkey;
    std::unordered_set<std::string> m_uv_account_pubkeys;
    std::unordered_map<std::string, std::shared_ptr<Block>> m_blocks;
    std::unordered_map<std::string, std::shared_ptr<Pending_Block>> m_pending_blocks;
    std::list<std::string> m_pending_block_hashes;
    bool m_is_switching = false;
    std::list<std::shared_ptr<Pending_Chain>> m_pending_brief_chains;
    std::list<std::shared_ptr<Pending_Chain>> m_brief_chains;
    std::unordered_map<std::string, std::shared_ptr<Pending_Brief_Request>> m_pending_brief_reqs;
    std::shared_ptr<Pending_Detail_Request> m_detail_request;
    Timer_Controller m_timer_ctl;
    std::unordered_set<std::string> m_pending_peer_keys;
    std::unordered_map<std::string, std::shared_ptr<Block>> m_tx_map;
    std::unordered_map<std::string, std::shared_ptr<Topic>> m_topics;
    std::unordered_map<uint64, std::list<std::shared_ptr<Topic>>> m_rollback_topics;
    std::unordered_map<uint64, std::pair<std::shared_ptr<Block>, std::list<std::string>>> m_rollback_txs;
    std::list<std::shared_ptr<Topic>> m_topic_list;
    std::list<std::shared_ptr<tx::Tx>> m_uv_1_txs;
    std::list<std::shared_ptr<tx::Tx>> m_uv_2_txs;
    std::unordered_set<std::string> m_uv_tx_ids;

    struct Tx_Comp
    {
        bool operator()(const std::shared_ptr<tx::Tx> &a, const std::shared_ptr<tx::Tx> &b)
        {
            return a->m_id < b->m_id;
        }
    };
    
    std::set<std::shared_ptr<tx::Tx>, Tx_Comp> m_uv_3_txs;
    std::array<char, 255> m_b64_table;
    std::shared_ptr<Account> m_reserve_fund_account;
    fly::base::Lock_Queue<std::unique_ptr<fly::net::Message<Json>>> m_peer_messages;
    fly::base::Lock_Queue<std::unique_ptr<fly::net::Message<Wsock>>> m_wsock_messages;
    
    struct {
        rapidjson::Value m_hash;
        rapidjson::Value m_sign;
        rapidjson::Value m_data;
    } m_broadcast_json;
};

#endif
