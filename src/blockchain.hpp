#ifndef BLOCKCHAIN
#define BLOCKCHAIN

#include <string>
#include <memory>
#include <map>
#include <unordered_set>
#include <unordered_map>
#include "fly/base/singleton.hpp"
#include "block.hpp"
#include "account.hpp"

class Blockchain : public fly::base::Singleton<Blockchain>
{
public:
    Blockchain();
    ~Blockchain();
    bool load(std::string db_path);
    bool get_account(std::string name, std::shared_ptr<Account> &account);
    bool get_account(uint64 id, std::shared_ptr<Account> &account);
    std::string sign(std::string privk_b64, std::string hash_b64);
    bool verify_sign(std::string pubk_b64, std::string hash_b64, std::string sign_b64);
    bool hash_pow(char hash_arr[32], uint32 zero_bits);
    
private:
    uint64 m_cur_db_block_id;
    std::string m_cur_db_block_hash;
    std::unordered_set<std::string> m_account_names;
    std::unordered_map<uint64, std::shared_ptr<Account>> m_account_by_id;
    std::map<uint64, std::shared_ptr<Block>> m_blocks;
    uint64 m_total;
    uint32 m_decimal;
    uint32 m_block_interval;
    uint32 m_last_irreversible_block;
    uint32 m_vote_activate_check_interval;
    uint64 m_vote_activate_min_coin_num;
    uint32 m_topic_expired_block_num;
    uint32 m_account_max_length;
    uint32 m_topic_max_length;
    uint32 m_topic_message_max_length;
    uint64 m_fee_max;
    uint32 m_tx_live_block_lifetime;
};

#endif
