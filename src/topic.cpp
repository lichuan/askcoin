#include "topic.hpp"

Topic::Topic(std::string key, std::string data, std::string block_hash, uint64 balance)
{
    m_key = key;
    m_data = data;
    m_block_hash = block_hash;
    m_balance = balance;
    m_total = balance;
    m_uv_reply = 0;
    m_uv_reward = 0;
}

Topic::~Topic()
{
}

void Topic::set_owner(std::shared_ptr<Account> owner)
{
    m_owner = owner;
}

std::shared_ptr<Account> Topic::get_owner()
{
    return m_owner;
}

const std::string& Topic::block_hash()
{
    return m_block_hash;
}

const std::string& Topic::key()
{
    return m_key;
}

bool Topic::get_reply(std::string key, std::shared_ptr<Reply> &reply)
{
    for(auto r : m_reply_list)
    {
        if(r->key() == key)
        {
            reply = r;

            return true;
        }
    }

    return false;
}

void Topic::add_balance(uint64 value)
{
    m_balance += value;
}

void Topic::sub_balance(uint64 value)
{
    m_balance -= value;
}

uint64 Topic::get_balance()
{
    return m_balance;
}

uint64 Topic::get_total()
{
    return m_total;
}

// todo, empty topic tracker
bool Topic::add_member(std::string tx_id, std::shared_ptr<Account> account)
{
    for(auto &p : m_members)
    {
        if(p.second == account)
        {
            return false;
        }
    }

    m_members.push_back(std::make_pair(tx_id, account));

    return true;
}
