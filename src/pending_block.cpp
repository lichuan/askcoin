#include "pending_block.hpp"
#include "block.hpp"

Pending_Block::Pending_Block(uint64 id, uint64 utc, uint32 version, uint32 zero_bits, std::string hash, std::string pre_hash)
{
    m_id = id;
    m_utc = utc;
    m_version = version;
    m_zero_bits = zero_bits;
    m_hash = hash;
    m_pre_hash = pre_hash;
}

void Pending_Block::add_difficulty_from(std::shared_ptr<Block> other)
{
    m_accum_pow = other->m_accum_pow;
    m_accum_pow.add_pow(m_zero_bits);
}

void Pending_Block::add_difficulty_from(std::shared_ptr<Pending_Block> other)
{
    m_accum_pow = other->m_accum_pow;
    m_accum_pow.add_pow(m_zero_bits);
}
