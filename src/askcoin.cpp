#include <fstream>
#include <fcntl.h>
#include <iostream>
#include <sys/stat.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "fly/init.hpp"
#include "fly/base/logger.hpp"
#include "compat/sanity.h"
#include "random.h"
#include "key.h"
#include "cryptopp/base64.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"
#include "utilstrencodings.h"
#include "rapidjson/istreamwrapper.h"
#include "rapidjson/error/en.h"
#include "version.hpp"
#include "p2p/node.hpp"
#include "wsock_node.hpp"
#include "blockchain.hpp"

using namespace CryptoPP;
using namespace rapidjson;
using namespace std;

static std::unique_ptr<ECCVerifyHandle> globalVerifyHandle;

/** Sanity checks
 *  Ensure that Bitcoin is running in a usable environment with all
 *  necessary library support.
 */
bool InitSanityCheck(void)
{
    if(!ECC_InitSanityCheck()) {
        CONSOLE_LOG_FATAL("Elliptic curve cryptography sanity check failure. Aborting.");
        return false;
    }

    if (!glibc_sanity_test() || !glibcxx_sanity_test())
        return false;

    if (!Random_SanityCheck()) {
        CONSOLE_LOG_FATAL("OS cryptographic RNG sanity check failure. Aborting.");
        return false;
    }

    return true;
}

bool AppInitSanityChecks()
{
    std::string sha256_algo = SHA256AutoDetect();
    CONSOLE_LOG_INFO("Using the '%s' SHA256 implementation", sha256_algo.c_str());
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

class Askcoin : public fly::base::Singleton<Askcoin>
{
public:
    
    int main()
    {
        //init library
        fly::init();

        std::ifstream ifs("./config.json");
        IStreamWrapper isw(ifs);
        Document doc;
        doc.ParseStream(isw);

        if(doc.HasParseError())
        {
            cout << "parse config.json failed: " << GetParseError_En(doc.GetParseError()) << endl;

            return EXIT_FAILURE;
        }

        if(!doc.HasMember("log_path"))
        {
            cout << "config.json don't contain log_path field!" << endl;

            return EXIT_FAILURE;
        }

        fly::base::Logger::instance()->init(fly::base::DEBUG, "askcoin", doc["log_path"].GetString());
        CONSOLE_LOG_INFO("start askcoin, version: %s, verno: %u", ASKCOIN_VERSION_NAME, ASKCOIN_VERSION);
        
        if (!AppInitSanityChecks())
        {
            CONSOLE_LOG_FATAL("sanity check failed");
            exit(EXIT_FAILURE);
        }
        if(!doc.HasMember("db_path"))
        {
            CONSOLE_LOG_FATAL("config.json don't contain db_path field!");

            return EXIT_FAILURE;
        }

        if(!Blockchain::instance()->load(doc["db_path"].GetString()))
        {
            return EXIT_FAILURE;
        }
        
        if(!doc.HasMember("network"))
        {
            CONSOLE_LOG_FATAL("config.json don't contain network field!");

            return EXIT_FAILURE;
        }

        if(!doc.HasMember("run_as_witness"))
        {
            CONSOLE_LOG_FATAL("config.json don't contain run_as_witness field!");

            return EXIT_FAILURE;
        }

        bool run_as_witness = doc["run_as_witness"].GetBool();
        std::string host = doc["network"]["host"].GetString();
        std::string peer_file = doc["network"]["p2p"]["peer_file"].GetString();
        uint32 p2p_port = doc["network"]["p2p"]["port"].GetUint();
        uint32 p2p_max_passive_conn = doc["network"]["p2p"]["max_passive_conn"].GetUint();
        uint32 p2p_max_active_conn = doc["network"]["p2p"]["max_active_conn"].GetUint();
        uint32 websocket_max_passive_conn = doc["network"]["websocket"]["max_passive_conn"].GetUint();
        uint32 websocket_port = doc["network"]["websocket"]["port"].GetUint();
        bool open_websocket = doc["network"]["websocket"]["open"].GetBool();
        Wsock_Node::instance()->set_max_passive_conn(websocket_max_passive_conn);
        p2p::Node::instance()->set_max_active_conn(p2p_max_active_conn);
        p2p::Node::instance()->set_max_passive_conn(p2p_max_passive_conn);
        p2p::Node::instance()->set_peer_file(peer_file);
        p2p::Node::instance()->set_as_witness(run_as_witness);
        p2p::Node::instance()->set_host(host);
        
        if(!p2p::Node::instance()->start(p2p_port))
        {
            return EXIT_FAILURE;
        }

        if(open_websocket)
        {            
            if(!Wsock_Node::instance()->start(websocket_port))
            {
                return EXIT_FAILURE;
            }
        }
        
        CONSOLE_LOG_INFO("Congratulations, start askcoin success!!!\n\n"
                         "the following commands are available:\n"
                         ">stop\n"
                         ">register_account\n"
                         ">register_account_fund_sign\n"
                         ">request_as_witness\n"
                         ">send_money\n"
                         "\nfor example, if you want to stop askcoin, yout can input 'stop' command:");
        
        std::thread cmd_thread([&]() {
            while(true) {
                cout << ">";
                std::string cmd_string;
                getline(cin, cmd_string);

                if(cmd_string.empty())
                {
                    continue;
                }

                char *p = NULL;
                vector<string> vec;
                fly::base::split_string(cmd_string, " \t", vec, &p);

                for(auto token : vec)
                {
                    cout << "token: " << token << endl;
                }
                
                if(cmd_string == "stop")
                {
                    Wsock_Node::instance()->stop();
                    p2p::Node::instance()->stop();
                    
                    break;
                }
            }
        });

        if(open_websocket)
        {
            Wsock_Node::instance()->wait();
        }

        p2p::Node::instance()->wait();
        cmd_thread.join();
        Shutdown();
        CONSOLE_LOG_INFO("stop askcoin success");

        return EXIT_SUCCESS;
    }
};

int main()
{
    return Askcoin::instance()->main();
}
