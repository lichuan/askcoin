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
#include "fly/net/addr.hpp"
#include "compat/sanity.h"
#include "random.h"
#include "key.h"
#include "rapidjson/istreamwrapper.h"
#include "rapidjson/error/en.h"
#include "version.hpp"
#include "net/p2p/node.hpp"
#include "net/api/wsock_node.hpp"
#include "blockchain.hpp"
#include "command.hpp"
#include "utilstrencodings.h"

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
        rapidjson::IStreamWrapper isw(ifs);
        rapidjson::Document doc;
        doc.ParseStream(isw);

        if(doc.HasParseError())
        {
            std::cout << "parse config.json failed: " << GetParseError_En(doc.GetParseError()) << std::endl;
            return EXIT_FAILURE;
        }

        if(!doc.HasMember("log_level"))
        {
            std::cout << "config.json don't contain log_level field!" << std::endl;
            return EXIT_FAILURE;
        }

        if(!doc.HasMember("log_path"))
        {
            std::cout << "config.json don't contain log_path field!" << std::endl;
            return EXIT_FAILURE;
        }

        std::string log_level_str = doc["log_level"].GetString();
        fly::base::LOG_LEVEL log_level;
        
        if(log_level_str == "debug")
        {
            log_level = fly::base::DEBUG;
        }
        else if(log_level_str == "info")
        {
            log_level = fly::base::INFO;
        }
        else if(log_level_str == "warn")
        {
            log_level = fly::base::WARN;
        }
        else if(log_level_str == "error")
        {
            log_level = fly::base::ERROR;
        }
        else if(log_level_str == "fatal")
        {
            log_level = fly::base::FATAL;
        }
        else
        {
            std::cout << "config.json log_level invalid!" << std::endl;
            return EXIT_FAILURE;
        }
        
        fly::base::Logger::instance()->init(log_level, "askcoin", doc["log_path"].GetString());
        std::string git_sha1_of_current_code = "";
        CONSOLE_LOG_INFO("start askcoin, version: %s, verno: %u, git_sha1: %s", ASKCOIN_VERSION_NAME, ASKCOIN_VERSION, git_sha1_of_current_code.c_str());
        
        if (!AppInitSanityChecks())
        {
            CONSOLE_LOG_FATAL("sanity check failed");
            return EXIT_FAILURE;
        }

        if(!doc.HasMember("db_path"))
        {
            CONSOLE_LOG_FATAL("config.json don't contain db_path field!");
            return EXIT_FAILURE;
        }

        if(!doc.HasMember("network"))
        {
            CONSOLE_LOG_FATAL("config.json don't contain network field!");
            return EXIT_FAILURE;
        }
        
        std::string host = doc["network"]["p2p"]["host"].GetString();
        uint16 p2p_port = doc["network"]["p2p"]["port"].GetUint();
        uint32 p2p_max_conn = doc["network"]["p2p"]["max_conn"].GetUint();
        
        if(p2p_max_conn == 0)
        {
            CONSOLE_LOG_FATAL("p2p max_conn must be greater than 0");            
            return EXIT_FAILURE;
        }
        
        net::p2p::Node::instance()->set_host(host);
        net::p2p::Node::instance()->set_max_conn(p2p_max_conn);
        const rapidjson::Value &init_peer = doc["network"]["p2p"]["init_peer"];
        std::string websocket_host = doc["network"]["websocket"]["host"].GetString();
        uint16 websocket_port = doc["network"]["websocket"]["port"].GetUint();
        bool open_websocket = doc["network"]["websocket"]["open"].GetBool();
        uint32 websocket_max_conn = doc["network"]["websocket"]["max_conn"].GetUint();
        
        if(websocket_max_conn == 0)
        {
            CONSOLE_LOG_FATAL("websocket max_conn must be greater than 0");            
            return EXIT_FAILURE;
        }

        net::api::Wsock_Node::instance()->set_max_conn(websocket_max_conn);

        if(!Blockchain::instance()->start(doc["db_path"].GetString()))
        {
            CONSOLE_LOG_FATAL("load from leveldb failed");
            return EXIT_FAILURE;
        }
        
        for(int32 i = 0; i < init_peer.Size(); ++i)
        {
            std::string host = init_peer[i]["host"].GetString();
            uint16 port = init_peer[i]["port"].GetUint();
            fly::net::Addr addr(host, port);
            net::p2p::Node::instance()->add_peer_score(std::make_shared<net::p2p::Peer_Score>(addr));
        }
        
        if(!net::p2p::Node::instance()->start(p2p_port))
        {
            return EXIT_FAILURE;
        }

        if(open_websocket)
        {            
            if(!net::api::Wsock_Node::instance()->start(websocket_host, websocket_port))
            {
                return EXIT_FAILURE;
            }
        }
        
        std::string cmd_tips = "\nthe following commands are available:\n"
            ">stop\n"
            ">reg_account [account_name] [avatar] [reg_sign]\n"
            ">gen_reg_sign [account_name]\n"
            ">gen_privkey\n"
            ">import_privkey [privkey]\n"
            ">send_coin [account_id] [amount] [memo]\n"
            ">get_balance\n"
            ">top100\n"
            ">enable_mine [true|false]\n"
            ">info\n"
            ">help\n"
            "\nfor example, if you want to stop askcoin, yout can input 'stop' command:";

        CONSOLE_LOG_INFO("Congratulations, start askcoin success!!!");
        std::cout << cmd_tips << std::endl;
        bool cmd_pushed = false;

        std::thread cmd_thread([&]() {
            using std::cout;
            using std::endl;
            while(true) {
                if(!cmd_pushed)
                {
                    cout << ">";
                }

                cmd_pushed = false;
                std::string cmd_string;
                getline(std::cin, cmd_string);
                
                if(cmd_string.empty())
                {
                    continue;
                }

                char *p = NULL;
                std::vector<std::string> vec;
                fly::base::split_string(cmd_string, " \t", vec, &p);

                if(vec.empty())
                {
                    continue;
                }
                
                auto iter = vec.begin();
                auto cmd = *iter++;
                uint32 param_num = 0;
                std::shared_ptr<Command> command = std::make_shared<Command>();
                command->m_cmd = cmd;
                
                while(iter != vec.end())
                {
                    auto param = *iter++;
                    
                    if(param_num < 3)
                    {
                        command->m_params[command->m_param_num++] = param;
                    }
                    
                    ++param_num;
                }
                
                if(cmd == "stop")
                {
                    if(param_num > 0)
                    {
                        cout << "stop doesn't need any param" << endl;
                        continue;
                    }
                    
                    if(open_websocket)
                    {
                        net::api::Wsock_Node::instance()->stop();
                    }
                    
                    net::p2p::Node::instance()->stop();
                    Blockchain::instance()->stop();
                    break;
                }
                
                if(cmd == "help")
                {
                    cout << cmd_tips << endl;
                    continue;
                }
                else if(cmd == "ulimit")
                {
                    system("ulimit -a");
                    continue;
                } 
                else if(cmd == "gen_privkey")
                {
                    if(param_num > 0)
                    {
                        cout << "gen_privkey doesn't need any param" << endl;
                        continue;
                    }
                }
                else if(cmd == "import_privkey")
                {
                    if(param_num != 1)
                    {
                        cout << "usage: import_privkey [privkey]" << endl;
                        continue;
                    }
                }
                else if(cmd == "gen_reg_sign")
                {
                    if(param_num != 1)
                    {
                        cout << "usage: gen_reg_sign [reg_name]" << endl;
                        continue;
                    }
                }
                else if(cmd == "reg_account")
                {
                    if(param_num != 3)
                    {
                        cout << "usage: reg_account [reg_name] [avatar] [reg_sign]" << endl;
                        continue;
                    }
                }
                else if(cmd == "send_coin")
                {
                    if(param_num != 2 && param_num != 3)
                    {
                        cout << "usage: send_coin [account_id] [amount] [memo]" << endl;
                        continue;
                    }
                }
                else if(cmd == "get_balance")
                {
                    if(param_num > 0)
                    {
                        cout << "get_balance doesn't need any param" << endl;
                        continue;
                    }
                }
                else if(cmd == "top100")
                {
                    if(param_num > 0)
                    {
                        cout << "top100 doesn't need any param" << endl;
                        continue;
                    }
                }
                else if(cmd == "info")
                {
                    if(param_num > 0)
                    {
                        cout << "info doesn't need any param" << endl;
                        continue;
                    }
                }
                else if(cmd == "enable_mine")
                {
                    if(param_num != 1)
                    {
                        cout << "usage: enable_mine [true|false]" << endl;
                        continue;
                    }
                }
                else
                {
                    cout << "invalid command: " << cmd << endl;
                    continue;
                }

                Blockchain::instance()->push_command(command);
                cmd_pushed = true;
            }
        });
        
        cmd_thread.join();
        
        if(open_websocket)
        {
            net::api::Wsock_Node::instance()->wait();
        }

        net::p2p::Node::instance()->wait();
        Blockchain::instance()->wait();
        Shutdown();
        CONSOLE_LOG_INFO("stop askcoin success");
        return EXIT_SUCCESS;
    }
};

int main()
{
    return Askcoin::instance()->main();
}
