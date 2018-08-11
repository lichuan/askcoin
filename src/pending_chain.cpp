#include "pending_chain.hpp"

Pending_Chain::Pending_Chain()
{
}

Pending_Chain::Pending_Chain(std::shared_ptr<net::p2p::Peer> peer, std::shared_ptr<Pending_Block> block, Accum_Pow declared_pow)
{
    m_req_blocks.push_back(block);
    m_declared_pow = declared_pow;
    m_remain_pow = declared_pow;
    m_peer = peer;
    m_start = 0;
    m_detail_attached = false;
    m_brief_attached = false;
}
