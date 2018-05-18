#include "account.hpp"
#include "utilstrencodings.h"
#include "blockchain.hpp"

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
    Blockchain::instance()->del_account_rich(shared_from_this());
    m_balance += value;
    Blockchain::instance()->add_account_rich(shared_from_this());
}

void Account::sub_balance(uint64 value)
{
    Blockchain::instance()->del_account_rich(shared_from_this());
    m_balance -= value;
    Blockchain::instance()->add_account_rich(shared_from_this());
}

void Account::set_balance(uint64 value)
{
    Blockchain::instance()->del_account_rich(shared_from_this());
    m_balance = value;
    Blockchain::instance()->add_account_rich(shared_from_this());
}

uint64 Account::id()
{
    return m_id;
}

std::string Account::name()
{
    return m_name;
}

void Account::add_history(History *history)
{
    m_history.push_back(history);
}

std::string Account::pubkey()
{
    return m_pubkey;
}

void Account::set_referrer(std::shared_ptr<Account> account)
{
    m_referrer = account;
}

std::shared_ptr<Account> Account::get_referrer()
{
    return m_referrer;
}

bool Account::join_topic(std::shared_ptr<Topic> topic)
{
    for(auto t : m_joined_topic_list)
    {
        if(t == topic)
        {
            return false;
        }
    }

    m_joined_topic_list.push_back(topic);

    return true;
}
