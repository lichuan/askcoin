#ifndef NET__P2P__MESSAGE
#define NET__P2P__MESSAGE

namespace net {
namespace p2p {

enum MSG_TYPE
{
    MSG_SYS,
    MSG_REG,
    MSG_TX,
    MSG_BLOCK,
    MSG_PROBE
};

enum MSG_CMD
{
    SYS_PING,
    SYS_PONG,
    SYS_PEER_REQ,
    SYS_PEER_RSP,
    
    REG_REQ = 0,
    REG_RSP,
    REG_VERIFY_REQ,
    REG_VERIFY_RSP,

    TX_BROADCAST = 0,

    BLOCK_BROADCAST = 0,
    BLOCK_BROADCAST_1,
    BLOCK_BRIEF_REQ,
    BLOCK_BRIEF_RSP,
    BLOCK_DETAIL_REQ,
    BLOCK_DETAIL_RSP
};

}
}

#endif
