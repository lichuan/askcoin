#include <list>
#include <sys/time.h>
#include "timer.hpp"

Timer::Timer(uint64 id, uint64 tick, std::function<void()> cb, uint32 interval_tick, bool oneshot)
{
    m_tick = tick;
    m_cb = cb;
    m_interval_tick = interval_tick;
    m_oneshot = oneshot;
    m_id = id;
}

Timer::~Timer()
{
}

uint64 Timer::now_msec()
{
    struct timeval _tv;
    gettimeofday(&_tv, NULL);
    uint64 now_msec = (uint64)_tv.tv_sec * 1000 + (uint64)_tv.tv_usec / 1000;

    return now_msec;
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
    uint64 now_tick = Timer::now_msec() / 100;
    uint64 interval_tick = interval / 100;
    uint64 id = m_id_allocator.new_id();
    std::shared_ptr<Timer> timer = std::make_shared<Timer>(id, now_tick + interval_tick, cb, interval_tick, oneshot);
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
    m_timer_map.erase(iter_timer);
    auto iter_end = m_timers.upper_bound(timer);
    
    for(auto iter = m_timers.lower_bound(timer); iter != iter_end; ++iter)
    {
        if(*iter == timer)
        {
            m_timers.erase(iter);
            return;
        }
    }
}

void Timer_Controller::reset_timer(uint64 id)
{
    uint64 now_tick = Timer::now_msec() / 100;
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
            timer->m_tick = now_tick + timer->m_interval_tick;
            m_timers.insert(timer);
            
            return;
        }
    }
}


bool Timer_Controller::run()
{
    uint64 now_tick = Timer::now_msec() / 100;
    std::unique_lock<std::mutex> lock(m_mutex);
    bool called = false;
    std::list<std::shared_ptr<Timer>> timers;
    
    for(auto iter = m_timers.begin(); iter != m_timers.end();)
    {
        std::shared_ptr<Timer> timer = *iter;

        if(timer->m_tick <= now_tick)
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
        lock.lock();
        
        if(!timer->m_oneshot)
        {
            timer->m_tick = now_tick + timer->m_interval_tick;
            
            if(m_timer_map.find(timer->m_id) != m_timer_map.end())
            {
                m_timers.insert(timer);
            }
        }
        else
        {
            m_timer_map.erase(timer->m_id);
        }
        
        lock.unlock();
    }
    
    return called;
}
