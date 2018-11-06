#ifndef NET__API__ERR_CODE
#define NET__API__ERR_CODE

namespace net {
namespace api {

enum EC
{
    ERR_TX_EXIST = 1,
    ERR_PUBKEY_EXIST,
    ERR_SIGN_EXPIRED,
    ERR_REG_FAILED,
    ERR_REG_WAIT,
    ERR_TX_EXPIRED,
    ERR_NAME_EXIST,
    ERR_REFERRER_NOT_EXIST,
    ERR_REFERRER_BALANCE_NOT_ENOUGH,
    ERR_PUBKEY_NOT_REGISTERED,
    ERR_BALANCE_NOT_ENOUGH,
    ERR_RECEIVER_NOT_EXIST,
    ERR_TOPIC_EXIST,
    ERR_TOPIC_NUM_EXCEED_LIMIT,
    ERR_TOPIC_NOT_EXIST,
    ERR_REPLY_NOT_EXIST,
    ERR_REPLY_NUM_EXCEED_LIMIT,
    ERR_JOINED_TOPIC_NUM_EXCEED_LIMIT,
    ERR_TOPIC_BALANCE_NOT_ENOUGH,
};

}
}

#endif
