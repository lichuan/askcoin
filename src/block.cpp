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

void Block::set_parent(std::shared_ptr<Block> parent)
{
    m_parent = parent;
}

void Block::add_child(std::shared_ptr<Block> child)
{
    m_children.push_back(child);
}

Pending_Block::Pending_Block(uint64 id, uint32 utc, uint32 version, uint32 zero_bits, std::string hash)
    : Block(id, utc, version, zero_bits, hash)
{
}

Pending_Block::~Pending_Block()
{
}
