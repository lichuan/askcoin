#include "net/api/user.hpp"

namespace net {
namespace api {

User::User()
{
    m_state = 0;
    m_timer_id = 0;
    m_reg_probe = false;
}

User::~User()
{
}

}
}
