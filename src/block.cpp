#include "block.hpp"

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

bool Block::is_genesis()
{
    return m_id == 0 && m_hash == "QKQzeV/UzpDNQDWZGVVU5vyKdTw9MmrTbOD/wfa480Y=";
}

bool Block::difficult_than(std::shared_ptr<Block> other)
{
    return m_accum_pow > other->m_accum_pow;
}

void Block::add_my_difficulty_to(std::shared_ptr<Block> other)
{
    other->m_accum_pow = m_accum_pow;
    other->m_accum_pow.add_pow(other->zero_bits());
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

void Block::set_miner(std::shared_ptr<Account> miner)
{
    m_miner = miner;
}

std::shared_ptr<Account> Block::get_miner()
{
    return m_miner;
}

Pending_Block::Pending_Block(uint64 id, uint64 utc, uint32 version, uint32 zero_bits, std::string hash)
    : Block(id, utc, version, zero_bits, hash)
{
}

Pending_Block::~Pending_Block()
{
}
