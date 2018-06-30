#include "pending_block.hpp"

Pending_Block::Pending_Block(uint64 id, uint64 utc, uint32 version, uint32 zero_bits, std::string hash, std::string pre_hash)
{
    m_id = id;
    m_utc = utc;
    m_version = version;
    m_zero_bits = zero_bits;
    m_hash = hash;
    m_pre_hash = pre_hash;
}
