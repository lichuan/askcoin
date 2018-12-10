#include "account.hpp"
#include "utilstrencodings.h"
#include "blockchain.hpp"

Account::Account(uint64 id, std::string name, std::string pubkey, uint32 avatar, uint64 block_id)
{
    m_id = id;
    m_name = name;
    m_pubkey = pubkey;
    m_balance = 0;
    m_avatar = avatar;
    m_uv_spend = 0;
    m_uv_topic = 0;
    m_uv_join_topic = 0;
    m_block_id = block_id;
}

Account::~Account()
{
}

uint64 Account::get_balance()
{
    return m_balance;
}

uint64 Account::block_id()
{
    return m_block_id;
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

const std::string& Account::name()
{
    return m_name;
}

uint32 Account::avatar()
{
    return m_avatar;
}

void Account::add_history(std::shared_ptr<History> history)
{
    m_history.push_back(history);
    
    while(m_history.size() > 200)
    {
        m_history.pop_front();
    }
}

void Account::pop_history()
{
    if(!m_history.empty())
    {
        m_history.pop_back();
    }
}

void Account::proc_history_expired(uint64 cur_block_id)
{
    while(!m_history.empty())
    {
        auto h = m_history.front();
        
        if(h->m_block_id + TOPIC_LIFE_TIME * 30 < cur_block_id)
        {
            m_history.pop_front();
        }
        else
        {
            break;
        }
    }
    
    while(m_history.size() > 200)
    {
        m_history.pop_front();
    }
}

const std::string& Account::pubkey()
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

void Account::leave_topic(std::shared_ptr<Topic> topic)
{
    for(auto iter = m_joined_topic_list.begin(); iter != m_joined_topic_list.end(); ++iter)
    {
        if(*iter == topic)
        {
            m_joined_topic_list.erase(iter);
            
            break;
        }
    }
}

bool Account::joined_topic(std::shared_ptr<Topic> topic)
{
    for(auto t : m_joined_topic_list)
    {
        if(t == topic)
        {
            return true;
        }
    }

    return false;
}
