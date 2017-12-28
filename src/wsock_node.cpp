#include "wsock_node.hpp"

using namespace std::placeholders;

Wsock_Node::Wsock_Node()
{
}

Wsock_Node::~Wsock_Node()
{
}

bool Wsock_Node::start(uint32 port)
{
    std::unique_ptr<fly::net::Server<Wsock>> server(new fly::net::Server<Wsock>(fly::net::Addr("0.0.0.0", port),
                                                                                std::bind(&Wsock_Node::allow, this, _1),
                                                                                std::bind(&Wsock_Node::init, this, _1),
                                                                                std::bind(&Wsock_Node::dispatch, this, _1),
                                                                                std::bind(&Wsock_Node::close, this, _1),
                                                                                std::bind(&Wsock_Node::be_closed, this, _1)));
    if(server->start())
    {
        LOG_INFO("start websocket node success");
        m_server = std::move(server);

        return true;
    }

    LOG_FATAL("start websocket node failed!");

    return false;
}

void Wsock_Node::stop()
{
    m_server->stop();
}

void Wsock_Node::wait()
{
    m_server->wait();
}

void Wsock_Node::set_max_conn(uint32 num)
{
    m_max_conn = num > 300 ? num : 300;
}

bool Wsock_Node::allow(std::shared_ptr<fly::net::Connection<Wsock>> connection)
{
    return true;
}

void Wsock_Node::init(std::shared_ptr<fly::net::Connection<Wsock>> connection)
{
    std::lock_guard<std::mutex> guard(m_mutex);
    m_connections[connection->id()] = connection;
    LOG_INFO("connection count: %u", m_connections.size());
}

void Wsock_Node::dispatch(std::unique_ptr<fly::net::Message<Wsock>> message)
{
    std::shared_ptr<fly::net::Connection<Wsock>> connection = message->get_connection();
    const fly::net::Addr &addr = connection->peer_addr();
    LOG_INFO("recv message from %s:%d raw_data: %s", addr.m_host.c_str(), addr.m_port, message->raw_data().c_str());
}
    
void Wsock_Node::close(std::shared_ptr<fly::net::Connection<Wsock>> connection)
{
    LOG_INFO("close connection from %s:%d", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
    std::lock_guard<std::mutex> guard(m_mutex);
    m_connections.erase(connection->id());
    LOG_INFO("connection count: %u", m_connections.size());
}
    
void Wsock_Node::be_closed(std::shared_ptr<fly::net::Connection<Wsock>> connection)
{
    LOG_INFO("connection from %s:%d be closed", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
    std::lock_guard<std::mutex> guard(m_mutex);
    m_connections.erase(connection->id());
    LOG_INFO("connection count: %u", m_connections.size());
}
