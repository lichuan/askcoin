#include <unistd.h>
#include <unordered_map>
#include <fcntl.h>
#include <sys/stat.h>
#include "fly/init.hpp"
#include "fly/net/server.hpp"
#include "fly/base/logger.hpp"
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "compat/sanity.h"
#include "random.h"
#include "key.h"

using namespace std::placeholders;
static std::unique_ptr<ECCVerifyHandle> globalVerifyHandle;


/** Sanity checks
 *  Ensure that Bitcoin is running in a usable environment with all
 *  necessary library support.
 */
bool InitSanityCheck(void)
{
    if(!ECC_InitSanityCheck()) {
        LOG_FATAL("Elliptic curve cryptography sanity check failure. Aborting.");
        return false;
    }

    if (!glibc_sanity_test() || !glibcxx_sanity_test())
        return false;

    if (!Random_SanityCheck()) {
        LOG_FATAL("OS cryptographic RNG sanity check failure. Aborting.");
        return false;
    }

    return true;
}

bool AppInitSanityChecks()
{
    std::string sha256_algo = SHA256AutoDetect();
    LOG_INFO("Using the '%s' SHA256 implementation", sha256_algo.c_str());
    RandomInit();
    ECC_Start();
    globalVerifyHandle.reset(new ECCVerifyHandle());

    if (!InitSanityCheck())
        return false;

    return true;
}



void Shutdown()
{
    globalVerifyHandle.reset();
    ECC_Stop();
}


// std::vector<unsigned char> vec1 = {0x04,0xa5,0xc1,0x77,0xb9,0xe4,0xb5,0xda,0x15,0xc5,0x0e,0x75,0x35,0xbf,0xdd,0xac,0xe5,0x91,0x88,0x32,0xb6,0x87,0x8d,0xac,0xab,0x53,0x51,0xe3,0x5e,0x90,0x17,0xda,0x80,0x6d,0x08,0x87,0x31,0xba,0x78,0x3d,0x04,0x27,0xbb,0x68,0x94,0x01,0x47,0x92,0xe8,0x4e,0x71,0xe2,0xca,0xd0,0x11,0x26,0x01,0x0c,0x4c,0x87,0x97,0xb4,0x2d,0xb8,0x29};
    
    // CPubKey pub(vec1);
    // std::vector<unsigned char> vec2 = {0x30,0x45,0x02,0x20,0x1f,0x02,0x39,0x9a,0xae,0x46,0x2c,0x09,0xd5,0x24,0x84,0x0c,0x88,0xc1,0xd5,0x06,0xea,0x7c,0x6c,0xe8,0x6f,0x71,0x03,0x29,0xbe,0x52,0x12,0xc8,0xc1,0x60,0x0e,0xd9,0x02,0x21,0x00,0x83,0x77,0xe8,0x93,0xd9,0xa4,0x74,0xc6,0x4b,0x37,0xb7,0x70,0xf5,0x85,0xa8,0x37,0xe3,0x3d,0x36,0xa1,0xf6,0xf2,0x73,0xfa,0x92,0xb4,0xd0,0x40,0x1e,0x9d,0xb7,0x26};
    
    // uint256 msg({0x31,0xcd,0xa2,0xab,0x84,0x52,0xa3,0x3d,0x1f,0x25,0x41,0x2e,0x56,0x8c,0x71,0x6d,0x5b,0xb8,0x01,0x45,0xf6,0xad,0xd2,0x6f,0x5f,0x24,0x70,0xf4,0x64,0x22,0xe6,0xf7});
    
    // if(pub.Verify(msg, vec2)) {
    //     LOG_INFO("sign success.............");
    //     return true;
    // }
    // LOG_ERROR("sign failed............");
    
using fly::net::Wsock;
#include <iostream>
using namespace std;


#include "leveldb/db.h"

class Askcoin : public fly::base::Singleton<Askcoin>
{
public:
    bool allow(std::shared_ptr<fly::net::Connection<Wsock>> connection)
    {
        return true;
    }
    
    void init(std::shared_ptr<fly::net::Connection<Wsock>> connection)
    {
        std::lock_guard<std::mutex> guard(m_mutex);
        m_connections[connection->id()] = connection;
        LOG_INFO("connection count: %u", m_connections.size());
    }
    
    void dispatch(std::unique_ptr<fly::net::Message<Wsock>> message)
    {
        std::shared_ptr<fly::net::Connection<Wsock>> connection = message->get_connection();
        const fly::net::Addr &addr = connection->peer_addr();
        LOG_INFO("recv message from %s:%d raw_data: %s", addr.m_host.c_str(), addr.m_port, message->raw_data().c_str());
    }
    
    void close(std::shared_ptr<fly::net::Connection<Wsock>> connection)
    {
        LOG_INFO("close connection from %s:%d", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
        std::lock_guard<std::mutex> guard(m_mutex);
        m_connections.erase(connection->id());
        LOG_INFO("connection count: %u", m_connections.size());
    }
    
    void be_closed(std::shared_ptr<fly::net::Connection<Wsock>> connection)
    {
        LOG_INFO("connection from %s:%d be closed", connection->peer_addr().m_host.c_str(), connection->peer_addr().m_port);
        std::lock_guard<std::mutex> guard(m_mutex);
        m_connections.erase(connection->id());
        LOG_INFO("connection count: %u", m_connections.size());
    }
    
    void main()
    {
        //init library
        fly::init();

        fly::base::Logger::instance()->init(fly::base::DEBUG, "server", "./log/");
        
        if (!AppInitSanityChecks())
        {
            // InitError will have been called with detailed error, which ends up on console
            LOG_FATAL("sanity check failed");
            exit(EXIT_FAILURE);
        }
        

        leveldb::DB *db;
        leveldb::Options options;
        options.create_if_missing = true;
        //options.error_if_exists = true;

        std::string tstr = "abcdefg";
        cout << tstr.c_str() << " size: " << tstr.size() << " length: " << tstr.length() << endl;
        tstr[3] = 0;
        cout << tstr.c_str() << " [3]=0 size: " << tstr.size() << " length: " << tstr.length() << endl;
        cout << "tstr[3] = " << tstr[3] << endl;
        
        leveldb::Status status = leveldb::DB::Open(options, "./db", &db);
        std::string res = status.ToString();
        LOG_INFO("status str: %s", res.c_str());

        std::string val;
        leveldb::Status s;

        for(int i = 0; i < 100; ++i)
        {
            std::string vv = fly::base::to_string(i);
            
            cout << "vv: " << vv << endl;
            
            s = db->Put(leveldb::WriteOptions(), std::string("block") + vv, "val is 123");
        
            if(s.ok()) s = db->Get(leveldb::ReadOptions(), "block456", &val);
            else
            {
                LOG_INFO("write first failed: %s", s.ToString().c_str());
            }
            if(s.ok()) s = db->Put(leveldb::WriteOptions(), "block456", val);
            else
            {
                LOG_INFO("get failed: %s", s.ToString().c_str());
            }
        
            if(s.ok()) s = db->Delete(leveldb::WriteOptions(), "block456");
            else
            {
                LOG_INFO("put failed: %s", s.ToString().c_str());
            }

            if(!s.ok())
            {
                LOG_INFO("delete failed: %s", s.ToString().c_str());
            }
        
            assert(s.ok());
        }
        

        return;
        
        
        
        //test tcp server
        std::unique_ptr<fly::net::Server<Wsock>> server(new fly::net::Server<Wsock>(fly::net::Addr("127.0.0.1", 8899),
                                                                      std::bind(&Askcoin::allow, this, _1),
                                                                      std::bind(&Askcoin::init, this, _1),
                                                                      std::bind(&Askcoin::dispatch, this, _1),
                                                                      std::bind(&Askcoin::close, this, _1),
                                                                      std::bind(&Askcoin::be_closed, this, _1)));

        if(server->start())
        {
            LOG_INFO("start server ok!");
            server->wait();
        }
        else
        {
            LOG_FATAL("start server failed");
        }
    }
    
private:
    std::unordered_map<uint64, std::shared_ptr<fly::net::Connection<Wsock>>> m_connections;
    std::mutex m_mutex;
};

int main()
{
    Askcoin::instance()->main();

    return 0;
}
