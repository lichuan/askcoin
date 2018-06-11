#ifndef NET__P2P__PEER
#define NET__P2P__PEER

#include "fly/net/connection.hpp"
#include "peer_score.hpp"

using fly::net::Json;

namespace net {
namespace p2p {

class Peer
{
public:
    Peer();
    ~Peer();
    const std::string& key() const;
    uint32 m_state;
    fly::net::Addr m_addr;
    uint32 m_remote_key;
    uint32 m_local_key;
    uint64 m_reg_conn_id;
    uint64 m_timer_id;
    uint64 m_ping_timer_id;
    std::shared_ptr<fly::net::Connection<Json>> m_connection;

private:
    std::string m_key;
};

}
}

#endif
