#ifndef TX__TX
#define TX__TX

#include "fly/base/common.hpp"
#include "net/p2p/peer.hpp"

namespace tx {

class Tx
{
public:
    std::string m_id; 
    uint32 m_type;
    uint64 m_block_id;
    uint64 m_utc;
    std::string m_pubkey;
    std::shared_ptr<net::p2p::Peer> m_peer;
    std::shared_ptr<rapidjson::Document> m_doc;
    uint8 m_broadcast_num = 0;
};

class Tx_Reg : public Tx
{
public:
    std::string m_register_name;
    std::string m_referrer_pubkey;
    uint32 m_avatar;
};

class Tx_Send : public Tx
{
public:
    std::string m_receiver_pubkey;
    uint64 m_amount;
};

class Tx_Topic : public Tx
{
public:
    uint64 m_reward;
};

class Tx_Reply : public Tx
{
public:
    std::string m_topic_key;
    std::string m_reply_to;
    uint32 m_uv_join_topic = 0;
};

class Tx_Reward : public Tx
{
public:
    std::string m_topic_key;
    std::string m_reply_to;
    uint64 m_amount;
};

}

#endif
