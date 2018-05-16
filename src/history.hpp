#ifndef HISTORY
#define HISTORY

#include "fly/base/common.hpp"

class History
{
public:
    History(uint32 type);
    virtual ~History();

protected:
    uint32 m_type;
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
