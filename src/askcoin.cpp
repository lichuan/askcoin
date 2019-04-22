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
            std::cout << "config.json doesn't contain log_level field!" << std::endl;
            return EXIT_FAILURE;
        }

        if(!doc.HasMember("log_path"))
        {
            std::cout << "config.json doesn't contain log_path field!" << std::endl;
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
        
        if(!fly::base::Logger::instance()->init(log_level, "askcoin", doc["log_path"].GetString()))
        {
            CONSOLE_ONLY("init logger failed");
            return EXIT_FAILURE;
        }
        
        std::string git_sha1_of_current_code = "";
        CONSOLE_LOG_INFO("start askcoin, version: %s, verno: %u, git_sha1: %s", ASKCOIN_VERSION_NAME, ASKCOIN_VERSION, git_sha1_of_current_code.c_str());
        
        if (!AppInitSanityChecks())
        {
            CONSOLE_LOG_FATAL("sanity check failed");
            return EXIT_FAILURE;
        }

        if(!doc.HasMember("db_path"))
        {
            CONSOLE_LOG_FATAL("config.json doesn't contain db_path field!");
            return EXIT_FAILURE;
        }

        bool repair_db = false;

        if(doc.HasMember("repair_db") && doc["repair_db"].IsTrue())
        {
            repair_db = true;
        }
        
        if(!doc.HasMember("network"))
        {
            CONSOLE_LOG_FATAL("config.json doesn't contain network field!");
            return EXIT_FAILURE;
        }

        if(doc.HasMember("merge_point"))
        {
            std::shared_ptr<Blockchain::Merge_Point> mp_ptr(new Blockchain::Merge_Point);
            auto &mp = doc["merge_point"];

            if(mp.HasMember("import"))
            {
                if(!mp["import"].IsObject())
                {
                    CONSOLE_LOG_FATAL("merge_point import should be object");
                    return EXIT_FAILURE;
                }

                auto &imp = mp["import"];
                
                if(!imp.HasMember("block_id"))
                {
                    CONSOLE_LOG_FATAL("merge_point import doesn't contain block_id field!");
                    return EXIT_FAILURE;
                }

                if(!imp.HasMember("block_hash"))
                {
                    CONSOLE_LOG_FATAL("merge_point import doesn't contain block_hash field!");
                    return EXIT_FAILURE;
                }

                if(!imp.HasMember("import_path"))
                {
                    CONSOLE_LOG_FATAL("merge_point import doesn't contain import_path field!");
                    return EXIT_FAILURE;
                }

                uint64 block_id = imp["block_id"].GetUint64();
                
                if(block_id == 0)
                {
                    CONSOLE_LOG_FATAL("merge_point import block_id must be greater than 0");
                    return EXIT_FAILURE;
                }

                std::string block_hash = imp["block_hash"].GetString();
            
                if(block_hash.empty())
                {
                    CONSOLE_LOG_FATAL("merge_point import block_hash can't be empty");
                    return EXIT_FAILURE;
                }

                if(block_hash.length() != 44 || !Blockchain::instance()->is_base64_char(block_hash))
                {
                    CONSOLE_LOG_FATAL("merge_point import block_hash is invalid");
                    return EXIT_FAILURE;
                }
                
                std::string import_path = imp["import_path"].GetString();
                
                if(import_path.empty())
                {
                    CONSOLE_LOG_FATAL("merge_point import_path can't be empty");
                    return EXIT_FAILURE;
                }

                mp_ptr->m_import_block_id = block_id;
                mp_ptr->m_import_block_hash = block_hash;
                mp_ptr->m_import_path = import_path;
            }
            
            if(mp.HasMember("export"))
            {
                if(!mp["export"].IsObject())
                {
                    CONSOLE_LOG_FATAL("merge_point export should be object");
                    return EXIT_FAILURE;
                }

                auto &exp = mp["export"];
                
                if(!exp.HasMember("block_id"))
                {
                    CONSOLE_LOG_FATAL("merge_point export doesn't contain block_id field!");
                    return EXIT_FAILURE;
                }

                if(!exp.HasMember("block_hash"))
                {
                    CONSOLE_LOG_FATAL("merge_point export doesn't contain block_hash field!");
                    return EXIT_FAILURE;
                }

                if(!exp.HasMember("export_path"))
                {
                    CONSOLE_LOG_FATAL("merge_point export doesn't contain export_path field!");
                    return EXIT_FAILURE;
                }

                uint64 block_id = exp["block_id"].GetUint64();
                
                if(block_id == 0)
                {
                    CONSOLE_LOG_FATAL("merge_point export block_id must be greater than 0");
                    return EXIT_FAILURE;
                }
                
                if(block_id < mp_ptr->m_import_block_id)
                {
                    CONSOLE_LOG_FATAL("merge_point export block_id can not be less than import block_id");
                    return EXIT_FAILURE;
                }
                
                std::string block_hash = exp["block_hash"].GetString();
                
                if(block_hash.empty())
                {
                    CONSOLE_LOG_FATAL("merge_point export block_hash can't be empty");
                    return EXIT_FAILURE;
                }

                if(block_hash.length() != 44 || !Blockchain::instance()->is_base64_char(block_hash))
                {
                    CONSOLE_LOG_FATAL("merge_point export block_hash is invalid");
                    return EXIT_FAILURE;
                }
                
                std::string export_path = exp["export_path"].GetString();
                
                if(export_path.empty())
                {
                    CONSOLE_LOG_FATAL("merge_point export_path can't be empty");
                    return EXIT_FAILURE;
                }

                mp_ptr->m_export_block_id = block_id;
                mp_ptr->m_export_block_hash = block_hash;
                mp_ptr->m_export_path = export_path;
            }
            
            
            Blockchain::instance()->m_merge_point = mp_ptr;
        }
        
        auto &network = doc["network"];
        
        if(!network.IsObject())
        {
            CONSOLE_LOG_FATAL("network field in config.json is not object!");
            return EXIT_FAILURE;
        }

        if(!network.HasMember("p2p"))
        {
            CONSOLE_LOG_FATAL("config.json doesn't contain network.p2p field!");
            return EXIT_FAILURE;
        }

        if(!network.HasMember("websocket"))
        {
            CONSOLE_LOG_FATAL("config.json doesn't contain network.websocket field!");
            return EXIT_FAILURE;
        }

        auto &websocket = network["websocket"];

        if(!websocket.IsObject())
        {
            CONSOLE_LOG_FATAL("network.websocket field in config.json is not object!");
            return EXIT_FAILURE;
        }

        if(websocket.HasMember("exchange"))
        {
            auto &exchange = websocket["exchange"];

            if(!exchange.HasMember("account_b64"))
            {
                CONSOLE_LOG_FATAL("exchange doesn't contain account_b64 field!");
                return EXIT_FAILURE;
            }

            if(!exchange.HasMember("account_id"))
            {
                CONSOLE_LOG_FATAL("exchange doesn't contain account_id field!");
                return EXIT_FAILURE;
            }

            if(!exchange.HasMember("password"))
            {
                CONSOLE_LOG_FATAL("exchange doesn't contain password field!");
                return EXIT_FAILURE;
            }
            
            std::string account_b64 = exchange["account_b64"].GetString();
            std::string password = exchange["password"].GetString();
            uint64 account_id = exchange["account_id"].GetUint64();
            std::shared_ptr<Blockchain::Exchange_Account> exchange_account(new Blockchain::Exchange_Account);
            exchange_account->m_id = account_id;
            exchange_account->m_name = account_b64;
            exchange_account->m_password = password;
            Blockchain::instance()->m_exchange_account = exchange_account;
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
        bool enable_websocket = doc["network"]["websocket"]["enable"].GetBool();
        uint32 websocket_max_conn = doc["network"]["websocket"]["max_conn"].GetUint();
        
        if(websocket_max_conn == 0)
        {
            CONSOLE_LOG_FATAL("websocket max_conn must be greater than 0");            
            return EXIT_FAILURE;
        }

        net::api::Wsock_Node::instance()->set_max_conn(websocket_max_conn);

        if(!Blockchain::instance()->start(doc["db_path"].GetString(), repair_db))
        {
            CONSOLE_LOG_FATAL("load from leveldb failed");
            return EXIT_FAILURE;
        }

        if(repair_db)
        {
            return EXIT_SUCCESS;
        }
        
        if(Blockchain::instance()->m_merge_point && Blockchain::instance()->m_merge_point->m_export_block_id > 0)
        {
            return EXIT_SUCCESS;
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

        if(enable_websocket)
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
            ">lock [password]\n"
            ">unlock [password]\n"
            ">enable_mine [true|false]\n"
            ">info\n"
            ">myinfo\n"
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
                    
                    if(enable_websocket)
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
                else if(cmd == "myinfo")
                {
                    if(param_num > 0)
                    {
                        cout << "myinfo doesn't need any param" << endl;
                        continue;
                    }
                }
                else if(cmd == "clear_peer")
                {
                    if(param_num > 0)
                    {
                        cout << "clear_peer doesn't need any param" << endl;
                        continue;
                    }
                }
                else if(cmd == "clear_uv_tx")
                {
                    if(param_num > 0)
                    {
                        cout << "clear_uv_tx doesn't need any param" << endl;
                        continue;
                    }
                }
                else if(cmd == "lock")
                {
                    if(param_num != 1)
                    {
                        cout << "usage: lock [password]" << endl;
                        continue;
                    }
                }
                else if(cmd == "unlock")
                {
                    if(param_num != 1)
                    {
                        cout << "usage: unlock [password]" << endl;
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
        
        if(enable_websocket)
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
