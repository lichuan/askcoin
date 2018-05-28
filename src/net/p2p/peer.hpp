#ifndef NET__P2P__PEER
#define NET__P2P__PEER

#include "fly/net/connection.hpp"

using fly::net::Json;

namespace net {
namespace p2p {

class Peer
{
public:
    Peer();
    ~Peer();
    uint32 m_state;
    fly::net::Addr m_addr;
    std::shared_ptr<fly::net::Connection<Json>> m_connection;
};

}
}

#endif
