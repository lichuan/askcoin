#include "net/p2p/peer_score.hpp"
#include "net/p2p/node.hpp"

namespace net {
namespace p2p {

Peer_Score::Peer_Score(const fly::net::Addr &addr, uint64 score)
{
    m_addr = addr;
    m_score = score;
    m_key = addr.m_host + ":" + fly::base::to_string(addr.m_port);
}

Peer_Score::~Peer_Score()
{
}

std::string Peer_Score::key() const
{
    return m_key;
}

const fly::net::Addr& Peer_Score::addr()
{
    return m_addr;
}

void Peer_Score::add_score(uint64 score)
{
    if(!Node::instance()->erase_peer_score(shared_from_this()))
    {
        return;
    }

    m_score += score;
    Node::instance()->insert_peer_score(shared_from_this());
}

void Peer_Score::sub_score(uint64 score)
{
    if(!Node::instance()->erase_peer_score(shared_from_this()))
    {
        return;
    }

    if(m_score > score)
    {
        m_score -= score;
    }
    else
    {
        m_score = 0;
    }

    Node::instance()->insert_peer_score(shared_from_this());
}

}
}
