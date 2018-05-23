#ifndef NET__P2P__PEER
#define NET__P2P__PEER

#include "fly/net/addr.hpp"

namespace net {
namespace p2p {

class Peer
{
public:
    struct Score_Comp
    {
        bool operator()(const Peer &a, const Peer &b)
        {
            return a.m_score > b.m_score;
        }
    };
    
    Peer(const fly::net::Addr &addr, uint64 score = 0);
    ~Peer();
    std::string key();
    
private:
    uint64 m_score;
    std::string m_key;
    fly::net::Addr m_addr;
};

}
}

#endif
