#include "pending_brief_request.hpp"

Pending_Brief_Request::Pending_Brief_Request()
{
    m_state = 0;
    m_try_num = 1;
    m_timer_id = 0;
}
