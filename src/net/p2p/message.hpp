#ifndef NET__P2P__MESSAGE
#define NET__P2P__MESSAGE

#include "fly/base/common.hpp"

namespace net {
namespace p2p {

enum MSG_TYPE
{
    MSG_SYS,
    MSG_REG,
};

enum MSG_CMD
{
    SYS_PING,
    SYS_PONG,
    REG_REQ = 0,
    REG_RSP,
    REG_VERIFY_REQ,
    REG_VERIFY_RSP
};

}
}

#endif
