#ifndef BLOCKCHAIN
#define BLOCKCHAIN

#include <string>
#include <memory>
#include <map>
#include <set>
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
    
    // "total": 1000000000000000000,
    // "decimal": 8,
    // "block_interval": 15,
    // "topic_lifetime": 60000,
    // "tx_lifetime": 100,
    // "referrer_reward": 50,
    // "reserve_fund_account": "reserve_fund",
    // "account_max_length": 15,
    // "topic_max_length": 200,
    // "reply_max_length": 300,
    // "memo_max_length": 100,
    // "tx_max_one_block": 1500

};

#endif
