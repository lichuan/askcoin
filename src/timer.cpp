#include <list>
#include "timer.hpp"

Timer::Timer(uint64 id, uint64 utc, std::function<void()> cb, uint32 interval, bool oneshot)
{
    m_utc = utc;
    m_cb = cb;
    m_interval = interval;
    m_oneshot = oneshot;
    m_id = id;
}

Timer::~Timer()
{
}

Timer_Controller::Timer_Controller()
{
}

Timer_Controller::~Timer_Controller()
{
}

void Timer_Controller::clear()
{
    std::lock_guard<std::mutex> guard(m_mutex);
    m_timers.clear();
    m_timer_map.clear();
}

uint64 Timer_Controller::add_timer(std::function<void()> cb, uint32 interval, bool oneshot)
{
    uint32 now = time(NULL);
    uint64 id = m_id_allocator.new_id();
    std::shared_ptr<Timer> timer = std::make_shared<Timer>(id, now + interval, cb, interval, oneshot);
    std::lock_guard<std::mutex> guard(m_mutex);
    m_timers.insert(timer);
    m_timer_map.insert(std::make_pair(id, timer));

    return id;
}

void Timer_Controller::del_timer(uint64 id)
{
    std::lock_guard<std::mutex> guard(m_mutex);
    auto iter_timer = m_timer_map.find(id);

    if(iter_timer == m_timer_map.end())
    {
        return;
    }

    std::shared_ptr<Timer> timer = iter_timer->second;
    auto iter_end = m_timers.upper_bound(timer);

    for(auto iter = m_timers.lower_bound(timer); iter != iter_end; ++iter)
    {
        if(*iter == timer)
        {
            m_timers.erase(iter);
            m_timer_map.erase(iter_timer);
            
            return;
        }
    }
}

void Timer_Controller::reset_timer(uint64 id)
{
    uint64 now = time(NULL);
    std::lock_guard<std::mutex> guard(m_mutex);
    auto iter_timer = m_timer_map.find(id);

    if(iter_timer == m_timer_map.end())
    {
        return;
    }
    
    std::shared_ptr<Timer> timer = iter_timer->second;
    auto iter_end = m_timers.upper_bound(timer);

    for(auto iter = m_timers.lower_bound(timer); iter != iter_end; ++iter)
    {
        if(*iter == timer)
        {
            m_timers.erase(iter);
            timer->m_utc = now + timer->m_interval;
            m_timers.insert(timer);
            
            return;
        }
    }
}

bool Timer_Controller::run()
{
    uint64 now = time(NULL);
    std::unique_lock<std::mutex> lock(m_mutex);
    bool called = false;
    std::list<std::shared_ptr<Timer>> timers;
    
    for(auto iter = m_timers.begin(); iter != m_timers.end();)
    {
        std::shared_ptr<Timer> timer = *iter;

        if(timer->m_utc <= now)
        {
            timers.push_back(timer);
            iter = m_timers.erase(iter);
        }
        else
        {
            break;
        }
    }
    
    lock.unlock();
    
    for(auto &timer : timers)
    {
        timer->m_cb();
        called = true;
            
        if(!timer->m_oneshot)
        {
            timer->m_utc = now + timer->m_interval;
            lock.lock();
            m_timers.insert(timer);
            lock.unlock();
        }
        else
        {
            m_timer_map.erase(timer->m_id);
        }
    }

    return called;
}
