#include <unistd.h>
#include "fly/base/logger.hpp"
#include "net/p2p/peer.hpp"

namespace net {
namespace p2p {

Peer::Peer()
{
    m_state = 0;
    m_timer_id = 0;
    m_ping_timer_id = 0;
    m_remote_key = 0;
    m_local_key = 0;
    m_reg_conn_id = 0;
}

Peer::~Peer()
{
}

const std::string& Peer::key() const
{
    if(m_key.empty())
    {
        m_key = m_addr.m_host + ":" + fly::base::to_string(m_addr.m_port);
    }

    return m_key;
}

}
}
