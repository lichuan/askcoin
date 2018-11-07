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

    ACCOUNT_IMPORT = 0,
    ACCOUNT_TOP100,
    ACCOUNT_PROBE,
    ACCOUNT_QUERY,
    
    TX_CMD = 0,
    
    BLOCK_SYNC = 0,

    TOPIC_PROBE = 0,
    TOPIC_REPLY_PROBE,
    TOPIC_LIST,
    TOPIC_DETAIL
};

}
}

#endif
