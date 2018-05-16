#include "history.hpp"

History::History(uint32 type)
{
    m_type = type;
}

History::~History()
{
}

Sendcoin_History::Sendcoin_History() : History(0)
{
}

Sendcoin_History::~Sendcoin_History()
{
}

Recvcoin_History::Recvcoin_History() : History(0)
{
}

Recvcoin_History::~Recvcoin_History()
{
}
