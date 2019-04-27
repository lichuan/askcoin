#ifndef BLOCK
#define BLOCK

#include <memory>
#include "accum_pow.hpp"

class Account;

class Block
{
public:
    Block(uint64 id, uint64 utc, uint32 version, uint32 zero_bits, std::string hash);
    uint32 version();
    uint64 utc();
    uint64 id();
    const std::string& hash();
    uint32 zero_bits();
    uint64 utc_diff();
    void set_utc_diff(uint64 value);
    void set_parent(std::shared_ptr<Block> parent);
    std::shared_ptr<Block> get_parent();
    bool difficult_than_me(std::shared_ptr<Block> other);
    bool difficult_than_me(const Accum_Pow &accum_pow);
    bool difficult_equal(const Accum_Pow &accum_pow);
    bool difficult_equal(std::shared_ptr<Block> other);
    void add_difficulty_from(std::shared_ptr<Block> other);
    void set_miner_pubkey(std::string pubkey);
    const std::string& miner_pubkey();
    std::shared_ptr<Account> get_miner();
    bool m_miner_reward = true;
    Accum_Pow m_accum_pow;
    bool m_in_main_chain = false;
    uint32 m_tx_num = 0;
    
private:
    uint64 m_id;
    uint64 m_utc;
    uint32 m_version;
    uint32 m_zero_bits;
    uint64 m_utc_diff;
    std::string m_hash;
    std::shared_ptr<Block> m_parent;
    std::string m_miner_pubkey;
};

#endif
