#include "p2p/node.hpp"

using namespace std::placeholders;

namespace p2p {

Node::Node()
{
}

Node::~Node()
{
}

bool Node::start(uint32 port)
{
    std::unique_ptr<fly::net::Server<Json>> server(new fly::net::Server<Json>(fly::net::Addr("0.0.0.0", port),
                                                                                std::bind(&Node::allow, this, _1),
                                                                                std::bind(&Node::init, this, _1),
                                                                                std::bind(&Node::dispatch, this, _1),
                                                                                std::bind(&Node::close, this, _1),
                                                                                std::bind(&Node::be_closed, this, _1)));
    if(server->start())
    {
        LOG_INFO("start p2p node success");
        m_server = std::move(server);

        return true;
    }

    LOG_FATAL("start p2p node failed!");

    return false;
}

void Node::stop()
{
    m_server->stop();
}

void Node::wait()
{
    m_server->wait();
}

void Node::set_max_active_conn(uint32 num)
{
    m_max_active_conn = num > 300 ? num : 300;
}

void Node::set_max_passive_conn(uint32 num)
{
    m_max_passive_conn = num > 300 ? num : 300;
}

bool Node::allow(std::shared_ptr<fly::net::Connection<Json>> connection)
{
    return true;
}

void Node::init(std::shared_ptr<fly::net::Connection<Json>> connection)
{
    std::lock_guard<std::mutex> guard(m_mutex);
    m_connections[connection->id()] = connection;
    LOG_INFO("connection count: %u", m_connections.size());
}

void Node::dispatch(std::unique_ptr<fly::net::Message<Json>> message)
{
    std::shared_ptr<fly::net::Connection<Json>> connection = message->get_connection();
    const fly::net::Addr &addr = connection->peer_addr();
    LOG_INFO("recv message from %s:%d raw_data: %s", addr.m_host.c_str(), addr.m_port, message->raw_data().c_str());
}
    
void Node::close(std::shared_ptr<fly::net::Connection<Json>> connection)
{
    LOG_INFO("close connection from %s:%d", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
    std::lock_guard<std::mutex> guard(m_mutex);
    m_connections.erase(connection->id());
    LOG_INFO("connection count: %u", m_connections.size());
}
    
void Node::be_closed(std::shared_ptr<fly::net::Connection<Json>> connection)
{
    LOG_INFO("connection from %s:%d be closed", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
    std::lock_guard<std::mutex> guard(m_mutex);
    m_connections.erase(connection->id());
    LOG_INFO("connection count: %u", m_connections.size());
}

}
