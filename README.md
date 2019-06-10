## Askcoin

Askcoin is a cryptocurrency for real-time Q&A and prediction platform. It has a built-in decentralized exchange, It was created for people to ask questions freely, to talk freely, to trade freely and to predict events freely. It's decentralized and ASIC-resistant, this is achieved by a new POW consensus algorithm.

As we all know, bitcoin is mined by calculating sha256, so whoever calculates sha256 fast will be able to produce new blocks before anyone else, this is exactly what ASIC mining machines on the market are good at.

In order to weaken the advantages of ASIC mining machine, the mining algorithm of askcoin uses sha256 combined with memory loading to resist ASIC machine. In askcoin, the speed of mining depends mainly on the speed of memory load, not the speed of sha256 calculation.





## System requirement (recommend)

### *Hardware requirements:*

| Resource |     Require      |
| :------: | :--------------: |
|   CPU    | 16 cores or more |
|  Memory  |   16G or more    |
|   Disk   |   100G or more   |
| Network  |   100Mb / sec    |



### *Operating system:*

Askcoin can run on any Linux distribution *(64bit and support c++11)* such as Centos, Ubuntu, Debian, etc.

The binary release archive on GitHub is currently built on CentOS 7.4





## Configuration

The configuration file (***config.json***) for askcoin is as follows:

```json
{
    "log_level": "info",
    "log_path": "./log",
    "db_path": "./db",
    "network": {
        "p2p": {
            "host": "here should be your host (domain or ip address)",
            "port": 18050,
            "max_conn": 1000,
            "init_peer": [
                {
                    "host": "node1.askcoin.me",
                    "port": 18050
                },
                {
                    "host": "node2.askcoin.me",
                    "port": 18050
                }
            ]
        },
        "websocket": {
            "enable": true,
            "host": "0.0.0.0",
            "port": 19050,
            "max_conn": 5000
        }
    }
}
```

- ***log_level***:  control the level of the log and the corresponding output content, its value can be "fatal", "error", "warn", "info", "debug".
- ***log_path***:  the directory in which the log files are stored.
- ***db_path***:  directory for storing leveldb database files.
- ***network.p2p.host***:  host address for P2P network communication (IP or domain name).
- ***network.p2p.port***:  port number for P2P network communication.
- ***network.p2p.max_conn***:  maximum number of P2P network connections allowed.
- ***network.p2p.init_peer***:  initial peer nodes in P2P networks.
- ***network.websocket.enable***:  whether to open websocket service.
- ***network.websocket.host***:  websocket address that mobile app or explorer can connect to. If you only want to provide internal network access, you can set this as a private address (such as 192.168.1.234).
- ***network.websocket.port***:  websocket port that mobile app or explorer can connect to.
- ***network.websocket.max_conn***:  maximum number of websocket connections allowed.





## Max open files

On the Linux system, you can get the limit of the number of open files on the current system by typing the following command:

```bash
ulimit -a
```

![max open files](res/files_limit.jpg)

If you want to provide websocket service on the full node to a large number of mobile app users, you need to increase the maximum number of open files allowed by the system. Here are two ways to do this:

- modify the ***/etc/security/limits.conf*** file (you can get how to do it by google)
- start askcoin by running the ***start.sh*** script in the release package

The following is the content of the ***start.sh*** script file:

```bash
#!/bin/bash
ulimit -HSn 50000
./askcoin
```





## Firewall ports

As described in the ***configuration*** section above, askcoin needs to open two ports in the firewall:

- P2P communication port (default 18050)
- Websocket service port (default 19050)





## Account model

Unlike Bitcoin, askcoin uses an account model, so before using askcoin, you have to register an account in the block chain. In askcoin, there are five types of transactions:

1. Register an account
2. Transfer
3. Ask a question (or topic)
4. Reply to a question
5. Reward a reply

In order to prevent DDoS attacks, 2 ASK fees will be deducted from the initiator of each transaction. But if you are registering an account, who will pay for it? That's what your referrer should do.

In askcoin, if you want to register an account, you need to enter your username, avatar, and the string signed by your referrer. When the full node receives your registration request, it will deduct 2 ASK from your referrer's account.

Of the 2 ASK fees paid for each transaction you initiate since then, 1 ASK will be paid to the miner's account that put the transaction in the block, and another 1 ASK will be paid to your referrer's account.





## Miner

If you want to be a miner, you need to do the following steps:

1. Synchronize your system time with global UTC time (using **crontab** and **ntpdate**)

2. Run the askcoin full node by executing the ***start.sh*** script

3. When your full node is successfully started, you will see the following output on the shell terminal:

   ![start](res/start.jpg)

   you can run this command: ***tail -f log/askcoin.log*** on linux shell terminal to check the log's output generated, waiting for your full node to synchronize to the latest block (new miners can use the "merge point" to dramatically reduce synchronization time, you can refer to [***askcoin-merge-point***](https://github.com/lichuan/askcoin-merge-point) for more information)

4. If you haven't registered an account before, you need to execute ***gen_privkey*** to generate a new private key:

   ![gen_privkey](res/gen_privkey.jpg)

5. Import your private key by executing ***import_privkey***:

   ![import_privkey](res/import_privkey.jpg)

6. Let a user who has registered an account in askcoin execute ***gen_reg_sign*** command to help you generate a signature string for your registration. When you register successfully, he or she will automatically become your referrer: (to make it easier for new users to register, we have released a web tool to generate signature strings for users to register: [***askcoin-gen-reg-sign***](https://github.com/lichuan/askcoin-gen-reg-sign) If you are a new user and need to register, you can generate the signature string through the following address:
   [http://generate.askcoin.me](http://generate.askcoin.me/) )

   ![gen_reg_sign](res/gen_reg_sign.jpg)

7. Now you can register a new account by executing the ***reg_account*** command, which requires entering your account name, your avatar ID (ranging from 1 to 100), and the signature string generated by your referrer:

   ![reg_account](res/reg_account.jpg)

   You need to wait patiently for the miner to put your registration request into the block. Usually it only takes about 20 seconds to get the miner's confirmation. You can confirm whether the registration is successful by executing ***get_balance***. If the output of this command shows that your balance is 0, it means that you have successfully registered. Otherwise, it means that you still need to wait for confirmation from the miner:

   ![get_balance](res/get_balance.jpg)

   When you register successfully, your account will automatically start mining, you can stop mining by executing the ***enable_mine*** command:

   ![enable_mine](res/enable_mine.jpg)





## Build

Askcoin is built through scons (2.5.1 compatible version). On CentOS 7.4, you can install it and some other dependency packages by running the following command:

```shell
yum install -y scons cmake3 gcc-c++ autoconf automake libtool
```

Askcoin is open-source now, so you can clone it and its submodules by executing the following command:

```shell
git clone https://github.com/lichuan/askcoin.git --recursive
```

You can then go to askcoin directory and compile askcoin's source code using ***scons*** command:

```shell
cd askcoin
scons
```





## Exchange API

If some centralized exchanges wish to list ASK coin, they can follow the steps described in this section.

1. Add an `exchange` field under the `websocket` field of the ***config.json*** file in the **full node** you run, then fill in the ID and name (base64) of the account representing the exchange wallet , and set a password to add a layer of security check:

   ```json
   {
       "log_level": "info",
       "log_path": "./log",
       "db_path": "./db",
       "network": {
           "p2p": {
               "host": "here should be your host (domain or ip address)",
               "port": 18050,
               "max_conn": 1000,
               "init_peer": [
                   {
                       "host": "node1.askcoin.me",
                       "port": 18050
                   },
                   {
                       "host": "node2.askcoin.me",
                       "port": 18050
                   }
               ]
           },
           "websocket": {
               "enable": true,
               "host": "0.0.0.0",
               "port": 19050,
               "max_conn": 5000,
               "exchange": {
                   "account_id": 123,
                   "account_b64": "ZXhjaGFuZ2VfdXNlcg==",
                   "password": "exchange_api_password"
               }
           }
       }
   }
   ```

2. Establish a websocket connection to your **full node** and send **EXCHANGE_LOGIN** message:

   ```javascript
   var WebSocket = require('ws');
   // change the following to your own account
   var exchange_account_id = 123;
   var exchange_account_b64 = "ZXhjaGFuZ2VfdXNlcg=="; // base64 of account name
   var exchange_password = "exchange_api_password";
   var exchange_account_privkey_str = "Vm1wSmQwMVhSWGxUYTJScVUwWktXRmxzVWtKaVJUQjN=";
   var privkey_buf = Buffer.from(exchange_account_privkey_str, 'base64');
   var exchange_account_privkey = ec.keyFromPrivate(privkey_buf);
   var pubkey_hex = exchange_account_privkey.getPublic('hex');
   var exchange_account_pubkey_b64 = Buffer.from(pubkey_hex, 'hex').toString('base64');
   var ws = new WebSocket('ws://your-full-node.com:19050');
   ws.on('open', function() {
       // send EXCHANGE_LOGIN message
       ws.send(JSON.stringify({
           msg_type: 6,
           msg_cmd: 0,
           msg_id: 0,
           account_id: exchange_account_id,
           account_b64: exchange_account_b64,
           password: exchange_password
           
           // If you miss some blocks due to network interruption or downtime,
           // you can add the following two fields to the next EXCHANGE_LOGIN message
           // to query the withdrawal and deposit records within the blocks.
           // block_id_from: 1000,
           // block_id_to: 2000
       }));
   });
   ```

   From now on, if someone transfers ASK coin to your exchange account, you will receive a real-time notification message (**EXCHANGE_NOTIFY_DEPOSIT**) containing the sender's account information, the amount of transfer and **memo**. You can identify the depositor's account according to the **memo**.

   Since **consensus algorithm** judges which chain is the **main chain** based on **cumulative difficulty**, it may abandon the current branch chain and switch to the new main chain many times in the process of consensus, it is these characteristics that you need to constantly send **EXCHANGE_DEPOSIT_TX_PROBE** messages to check whether the transaction receives enough confirmations from miners.

3. If someone initiates withdrawal of ASK coin, the first thing to do is to construct an **ACCOUNT_QUERY** message, fill in the ID of the account, and then send it to your **full node** to query the public key string of the account ID.

   ```javascript
   function request_for_withdrawal(user_name, receiver_id, receiver_name, amount,memo)
   {
       if(balance_of_each_user[user_name] < amount) {
           console.log("Your account balance is insufficient");
           return;
       }
   
       withdraw_unique_id += 1;
       
       // Query the corresponding account public key
       // from the Full-node according to the account ID
       ws.send(JSON.stringify({ // send ACCOUNT_QUERY message
           msg_type: 1,
           msg_cmd: 3,
           msg_id: withdraw_unique_id,
           id: receiver_id
       }));
       
       var pre_withdraw = {};
       pre_withdraw.sender_name = user_name;
       pre_withdraw.receiver_id = receiver_id;
       pre_withdraw.receiver_name = receiver_name;
       pre_withdraw.amount = amount;
       pre_withdraw.memo = memo
       pre_pending_withdraw_txs[withdraw_unique_id] = pre_withdraw;
       console.log("withdraw_unique_id:", withdraw_unique_id);
   }
   ```

   When you query the public key corresponding to the account id, you need to construct a transfer transaction, fill in the recipient's public key, transfer amount and other information, and calculate the transaction ID of the transaction, and use your private key to sign the transaction, and finally send the transaction to your **full node** again.

   ```js
   if(msg_obj.msg_type == 1 && msg_obj.msg_cmd == 3) // ACCOUNT_QUERY
   {
       var pre_withdraw = pre_pending_withdraw_txs[msg_obj.msg_id];
   
       if(msg_obj.err_code == 12) // ERR_RECEIVER_NOT_EXIST
       {
           console.log("receiver not exist");
           pre_pending_withdraw_txs[msg_obj.msg_id] = null;
           return;
       }
   
       var buf = Buffer.from(pre_withdraw.receiver_name);
       var receiver_b64 = buf.toString('base64');
   
       if(receiver_b64 != msg_obj.name) {
           console.log("your receiver_name does not match the one from full-node");
           pre_pending_withdraw_txs[msg_obj.msg_id] = null;
           return;
       }
   
       // sendcoin
       var data_obj = {};
       data_obj.type = 2;
       data_obj.pubkey = exchange_account_pubkey_b64;
       var utc = (Date.now() / 1000);
       data_obj.utc = parseInt(utc);
       data_obj.block_id = latest_block_id;
       data_obj.fee = 2;
       data_obj.amount = pre_withdraw.amount;
   
       if(pre_withdraw.memo && pre_withdraw.memo.length > 0) {
           data_obj.memo = Buffer.from(pre_withdraw.memo).toString('base64');
       }
   
       data_obj.receiver = msg_obj.pubkey;
       var tx_hash_raw = hash.sha256().update(hash.sha256().update(JSON.stringify(data_obj)).digest()).digest();
       var tx_id = Buffer.from(tx_hash_raw).toString('base64');
       var sign = exchange_account_privkey.sign(tx_hash_raw).toDER();
       var sign_b64 = Buffer.from(sign).toString('base64');
       ws.send(JSON.stringify({
           msg_type: 2,
           msg_cmd: 0,
           msg_id: 0,
           sign: sign_b64,
           data: data_obj
       }));
   
       var withdraw_info = {};
       withdraw_info.sender_name = pre_withdraw.sender_name;
       withdraw_info.tx_id = tx_id;
       withdraw_info.block_id = data_obj.block_id;
       withdraw_info.utc = data_obj.utc;
       withdraw_info.receiver_name = pre_withdraw.receiver_name;
       withdraw_info.receiver_id = pre_withdraw.receiver_id;
       withdraw_info.amount = pre_withdraw.amount;
       withdraw_info.memo = data_obj.memo;
       pending_withdraw_txs[tx_id] = withdraw_info;
       pre_pending_withdraw_txs[withdraw_unique_id] = null;
   }
   ```

4. Similar to the **EXCHANGE_DEPOSIT_TX_PROBE** message, the withdrawal process also needs to send **EXCHANGE_WITHDRAW_TX_PROBE** message periodically to confirm whether enough confirmations have been received from miners.

   ```javascript
   setTimeout(function() {
       // send EXCHANGE_WITHDRAW_TX_PROBE message
       ws.send(JSON.stringify({
           msg_type: 6,
           msg_cmd: 3,
           msg_id: 0,
           block_id: withdraw_info.block_id,
           tx_id: tx_id
       }));
   }, 10000);
   ```

You can refer to the [***exchange_api.js***](api_usage/exchange_api.js) file in the **api_usage** directory for a complete usage of the exchange api, which contains all the examples needed for deposit and withdrawal.





## Generate registration string programmatically

If you want to generate registration string for new users programmatically, you can do like this:

```javascript
// how to generate registration sign string
var data_obj = {};
data_obj.block_id = latest_block_id;
data_obj.fee = 2;
data_obj.name = Buffer.from("username").toString('base64');

// change the public key in the following line to your own
data_obj.referrer = 'BC9YHbvohhgCxA+8FbHbcJozcVKl0W9ltw3veDxzO066ulbmu19Hb4kY2OS3NnNmIDFNKSzh8fjl7u6KqcUoWQA=';
var data_obj_hash_raw = hash.sha256().update(hash.sha256().update(JSON.stringify(data_obj)).digest()).digest();
var sign = your_privkey.sign(data_obj_hash_raw).toDER();
var sign_b64 = Buffer.from(sign).toString('base64');
var sign_string = '{"sign":"' + sign_b64 + '","sign_data":' + JSON.stringify(data_obj) + '}';
console.log("sign_string is:", sign_string);
```

You can refer to the [***askcoin-gen-reg-sign***](https://github.com/lichuan/askcoin-gen-reg-sign) for a complete usage of the process of generating registration string.





## Explorer & Mobile app

- Block explorer: https://github.com/lichuan/askcoin-explorer
- Mobile app: https://github.com/lichuan/askcoin-client





## Big data on the chain

With more and more users and transactions, the data on the block chain will become larger and larger. This will bring higher and higher costs to the people who run the full node. In fact, since the beginning of askcoin's design, the problem of data expansion on the chain has been considered. Askcoin is designed to focus on decentralization and real-time Q&A, the lifetime of each topic (or question) is about one day (equivalent to 4320 block intervals). When you run askcoin for several years, the amount of data on the chain may exceed what you can accept, you can freely cut out the expired topics from the chain and choose a widely accepted block as the merging point. You can safely delete all previous blocks, just keep all account information generated until the merge point. This process is also called pruning and merging. As long as the protocol of communication between all nodes remains unchanged or compatible, there will be no adverse impact, you can refer to [***askcoin-merge-point***](https://github.com/lichuan/askcoin-merge-point) for more information.

![merge](res/merge.jpg)





## Donation

At present, the development of askcoin is funded by ourselves. If you want to provide some financial assistance for this project, you can transfer some BTC to the address below:

**1HiAvroczUyjBWQTCfZJigAB5QoUeP1U7S**

Thank you for your support !

