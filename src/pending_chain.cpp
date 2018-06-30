#include "pending_chain.hpp"

Pending_Chain::Pending_Chain(std::shared_ptr<net::p2p::Peer> peer, std::shared_ptr<Pending_Block> block, Accum_Pow declared_pow)
{
    m_block = block;
    m_blocks.push_back(block);
    m_declared_pow = declared_pow;
    m_remain_pow = declared_pow;
    m_peers.push_back(peer);
    m_same_chain_peers.push_back(peer);
}
