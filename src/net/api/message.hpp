#ifndef NET__API__MESSAGE
#define NET__API__MESSAGE

namespace net {
namespace api {

enum MSG_TYPE
{
    MSG_SYS,
    MSG_ACCOUNT,
    MSG_TX,
    MSG_BLOCK,
    MSG_TOPIC
};

enum MSG_CMD
{
    SYS_PING,
    SYS_PONG,
    SYS_INFO,
    
    ACCOUNT_NEW = 0,
    ACCOUNT_LOGIN,
    ACCOUNT_TOP100,
    
    TX_SEND = 0,

    BLOCK_SYNC = 0,

    TOPIC_NEW = 0,
    TOPIC_REPLY,
    TOPIC_REWARD,
};

}
}

#endif
