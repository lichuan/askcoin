#include "history.hpp"

History::History(TYPE type)
{
    m_type = type;
}

History::~History()
{
}

Sendcoin_History::Sendcoin_History() : History(SEND_COIN)
{
}

Sendcoin_History::~Sendcoin_History()
{
}

Recvcoin_History::Recvcoin_History() : History(RECV_COIN)
{
}

Recvcoin_History::~Recvcoin_History()
{
}
