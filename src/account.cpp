#include "account.hpp"
#include "utilstrencodings.h"

Account::Account(uint64 id, std::string name, std::string pubkey, uint32 avatar)
{
    m_id = id;
    m_name = name;
    m_pubkey = pubkey;
    m_balance = 0;
    m_avatar = avatar;
}

Account::~Account()
{
}

uint64 Account::get_balance()
{
    return m_balance;
}

void Account::add_balance(uint64 value)
{
    m_balance += value;
}

void Account::set_balance(uint64 value)
{
    m_balance = value;
}

void Account::add_history(History *history)
{
    m_history.push_back(history);
}

std::string Account::pubkey()
{
    return m_pubkey;
}
