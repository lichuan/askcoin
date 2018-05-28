#include <unistd.h>
#include "fly/base/logger.hpp"
#include "net/p2p/peer.hpp"

namespace net {
namespace p2p {

Peer::Peer()
{
    m_state = 0;
}

Peer::~Peer()
{
}

}
}
