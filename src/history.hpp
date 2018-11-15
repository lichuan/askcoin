#ifndef HISTORY
#define HISTORY

#include "fly/base/common.hpp"

enum HISTORY_TYPE
{
    HISTORY_REG_FEE = 1,
    HISTORY_REFERRER_REWARD,
    HISTORY_NEW_TOPIC_FEE,
    HISTORY_NEW_TOPIC_REWARD,
    HISTORY_REPLY_FEE,
    HISTORY_SEND_FEE,
    HISTORY_SEND_TO,
    HISTORY_SEND_FROM,
    HISTORY_REWARD_FEE,
    HISTORY_REWARD_FROM,
    HISTORY_MINER_TX_REWARD,
    HISTORY_MINER_BLOCK_REWARD
};

class History
{
public:
    History(uint32 type)
    {
        m_type = type;
        m_change = 0;
        m_target_id = 0;
        m_target_avatar = 0;
        m_block_id = 0;
        m_utc = 0;
    }

    History()
    {
        m_type = 0;
        m_change = 0;
        m_target_id = 0;
        m_target_avatar = 0;
        m_block_id = 0;
        m_utc = 0;
    }

    uint32 m_type;
    uint64 m_change;
    uint64 m_target_id;
    uint32 m_target_avatar;
    std::string m_target_name;
    uint64 m_block_id;
    std::string m_memo;
    uint64 m_utc;
};

#endif
