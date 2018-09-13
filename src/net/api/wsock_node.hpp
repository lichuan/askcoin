#ifndef NET__API__WSOCK_NODE
#define NET__API__WSOCK_NODE

#include <unordered_map>
#include "fly/net/server.hpp"
#include "fly/base/singleton.hpp"
#include "net/api/user.hpp"
#include "timer.hpp"

using fly::net::Wsock;

namespace net {
namespace api {

class Wsock_Node : public fly::base::Singleton<Wsock_Node>
{
public:
    Wsock_Node();
    ~Wsock_Node();

    bool start(std::string host, uint16 port);
    void stop();
    void wait();
    void set_max_conn(uint32 num);
    bool init(std::shared_ptr<fly::net::Connection<Wsock>> connection);
    void dispatch(std::unique_ptr<fly::net::Message<Wsock>> message);
    void close(std::shared_ptr<fly::net::Connection<Wsock>> connection);
    void be_closed(std::shared_ptr<fly::net::Connection<Wsock>> connection);
    void timer_proc();
    
private:
    uint32 m_max_conn = 0;
    std::atomic<bool> m_stop{false};
    std::unordered_map<uint64, std::shared_ptr<User>> m_users;
    std::mutex m_mutex;
    std::unique_ptr<fly::net::Server<Wsock>> m_server;
    std::thread m_timer_thread;
    Timer_Controller m_timer_ctl;
};

}
}

#endif
