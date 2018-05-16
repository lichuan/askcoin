#include "topic.hpp"

Topic::Topic(std::string key, std::string data, uint64 block_id, uint64 balance)
{
    m_key = key;
    m_data = data;
    m_block_id = block_id;
    m_balance = balance;
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

uint64 Topic::block_id()
{
    return m_block_id;
}

std::string Topic::key()
{
    return m_key;
}

bool Topic::get_reply(std::string key, std::shared_ptr<Reply> &reply)
{
    auto iter = m_replies.find(key);

    if(iter == m_replies.end())
    {
        return false;
    }

    reply = iter->second;

    return true;
}

void Topic::add_reply(std::string key, std::shared_ptr<Reply> reply)
{
    m_replies.insert(std::make_pair(key, reply));
}

void Topic::sub_balance(uint64 value)
{
    m_balance -= value;
}

uint64 Topic::get_balance()
{
    return m_balance;
}
