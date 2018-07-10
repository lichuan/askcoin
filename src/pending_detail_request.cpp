#include "pending_detail_request.hpp"

Pending_Detail_Request::Pending_Detail_Request()
{
    m_state = 0;
    m_try_num = 1;
    m_timer_id = 0;
}
