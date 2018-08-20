#ifndef BLOCK
#define BLOCK

#include <memory>
#include "account.hpp"
#include "accum_pow.hpp"

class Block
{
public:
    Block(uint64 id, uint64 utc, uint32 version, uint32 zero_bits, std::string hash);
    bool is_genesis();
    uint32 version();
    uint64 utc();
    uint64 id();
    std::string hash();
    uint32 zero_bits();
    uint64 utc_diff();
    void set_parent(std::shared_ptr<Block> parent);
    std::shared_ptr<Block> get_parent();
    bool difficult_than(std::shared_ptr<Block> other);
    bool difficult_than_me(const Accum_Pow &accum_pow);
    bool difficult_equal(const Accum_Pow &accum_pow);
    void add_my_difficulty_to(std::shared_ptr<Block> other);
    void set_miner(std::shared_ptr<Account> miner);
    std::shared_ptr<Account> get_miner();
    bool m_miner_reward = true;
    Accum_Pow m_accum_pow;
    
private:
    uint64 m_id;
    uint64 m_utc;
    uint32 m_version;
    uint32 m_zero_bits;
    uint64 m_utc_diff;
    std::string m_hash;
    std::shared_ptr<Block> m_parent;
    std::shared_ptr<Account> m_miner;
};

#endif
