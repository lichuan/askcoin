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

void Peer_Score::add_score(uint64 score)
{
    Node::instance()->del_peer_score(shared_from_this());
    m_score += score;
    Node::instance()->add_peer_score(shared_from_this());
}

void Peer_Score::set_score(uint64 score)
{
    Node::instance()->del_peer_score(shared_from_this());
    m_score = score;
    Node::instance()->add_peer_score(shared_from_this());
}

void Peer_Score::sub_score(uint64 score)
{
    Node::instance()->del_peer_score(shared_from_this());

    if(m_score > score)
    {
        m_score -= score;
    }

    Node::instance()->add_peer_score(shared_from_this());
}

}
}
