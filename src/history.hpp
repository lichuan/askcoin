#ifndef HISTORY
#define HISTORY

#include "fly/base/common.hpp"
#include "transaction.hpp"

class History
{
public:
    enum TYPE
    {
        INVALID = 0,
        VOTE_PARAMS = Transaction::VOTE_PARAMS,
        BLOCK_REWARD = Transaction::BLOCK_REWARD,
        REG_ACCOUNT = Transaction::REG_ACCOUNT,
        SEND_COIN = Transaction::SEND_COIN,
        RECV_COIN,
        GENESIS_COIN,
        MAX
    };

    History(TYPE type);
    virtual ~History();

protected:
    TYPE m_type;
    uint64 m_change;
    uint64 m_balance;
};

class Sendcoin_History : public History
{
public:
    Sendcoin_History();
    ~Sendcoin_History();

    std::string m_receiver;
};

class Recvcoin_History : public History
{
public:
    Recvcoin_History();
    ~Recvcoin_History();
    
    std::string m_sender;
};

#endif
