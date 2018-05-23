#include "net/p2p/peer.hpp"

namespace net {
namespace p2p {

Peer::Peer(const fly::net::Addr &addr, uint64 score = 0)
{
    m_addr = addr;
    m_score = score;
    m_key = addr.m_host + ":" + fly::base::to_string(addr.m_port);
}

Peer::~Peer()
{
}

std::string Peer::key()
{
    return m_key;
}

}
}
