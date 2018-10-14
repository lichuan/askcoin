#include "block.hpp"
#include "blockchain.hpp"

Block::Block(uint64 id, uint64 utc, uint32 version, uint32 zero_bits, std::string hash)
{
    m_id = id;
    m_utc = utc;
    m_version = version;
    m_zero_bits = zero_bits;
    m_hash = hash;
    m_utc_diff = 0;
}

uint64 Block::id()
{
    return m_id;
}

uint32 Block::version()
{
    return m_version;
}

uint64 Block::utc()
{
    return m_utc;
}

uint64 Block::utc_diff()
{
    return m_utc_diff;
}

uint32 Block::zero_bits()
{
    return m_zero_bits;
}

std::string Block::hash()
{
    return m_hash;
}

bool Block::difficult_than_me(std::shared_ptr<Block> other)
{
    return other->m_accum_pow > m_accum_pow;
}

bool Block::difficult_than_me(const Accum_Pow &accum_pow)
{
    return accum_pow > m_accum_pow;
}

bool Block::difficult_equal(const Accum_Pow &accum_pow)
{
    return m_accum_pow == accum_pow;
}

bool Block::difficult_equal(std::shared_ptr<Block> other)
{
    return m_accum_pow == other->m_accum_pow;
}

void Block::add_difficulty_from(std::shared_ptr<Block> other)
{
    m_accum_pow = other->m_accum_pow;
    m_accum_pow.add_pow(m_zero_bits);
}

void Block::set_parent(std::shared_ptr<Block> parent)
{
    m_parent = parent;
    m_utc_diff = m_utc - parent->m_utc;
}

std::shared_ptr<Block> Block::get_parent()
{
    return m_parent;
}

void Block::set_miner_pubkey(std::string pubkey)
{
    m_miner_pubkey = pubkey;
}

std::shared_ptr<Account> Block::get_miner()
{
    std::shared_ptr<Account> miner;
    Blockchain::instance()->get_account(m_miner_pubkey, miner);
    
    return miner;
}
