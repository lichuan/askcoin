#include "block.hpp"

Block::Block(uint64 id, uint32 utc, uint32 version, uint32 zero_bits, std::string hash)
{
    m_id = id;
    m_utc = utc;
    m_version = version;
    m_zero_bits = zero_bits;
    m_hash = hash;
}

uint64 Block::id()
{
    return m_id;
}

uint32 Block::version()
{
    return m_version;
}

uint32 Block::utc()
{
    return m_utc;
}

std::string Block::hash()
{
    return m_hash;
}
