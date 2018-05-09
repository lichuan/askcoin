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
    bool verify_hash(std::string block_hash, std::string block_data, uint32 zero_bits);
    bool hash_pow(char hash_arr[32], uint32 zero_bits);
    
private:
    uint64 m_cur_db_block_id;
    std::string m_cur_db_block_hash;
    uint64 m_cur_account_id;
    std::unordered_set<std::string> m_account_names;
    std::unordered_map<uint64, std::shared_ptr<Account>> m_account_by_id;
    std::unordered_map<std::string, std::shared_ptr<Account>> m_account_by_pubkey;
    std::unordered_map<std::string, std::shared_ptr<Block>> m_blocks;
};

#endif
