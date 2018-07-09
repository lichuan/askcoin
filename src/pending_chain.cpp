#include "pending_chain.hpp"

Pending_Chain::Pending_Chain()
{
}

Pending_Chain::Pending_Chain(std::shared_ptr<net::p2p::Peer> peer, std::shared_ptr<Pending_Block> block, Accum_Pow declared_pow)
{
    m_brief_req_state.m_cur_block = block;
    m_block_hashes.push_back(block->m_hash);
    m_declared_pow = declared_pow;
    m_remain_pow = declared_pow;
    m_peer = peer;
}
