// If your exchange is willing to list Askcoin,
// you can refer to the API usage described in
// this file to integrate it into your own system

var hash = require('hash.js');
const { randomBytes } = require('crypto')
var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var WebSocket = require('ws');

// //..............................C++ Full-node websocket api message enum.............................
// enum MSG_TYPE
// {
//     MSG_SYS,
//     MSG_ACCOUNT,
//     MSG_TX,
//     MSG_BLOCK,
//     MSG_TOPIC,
//     MSG_EXPLORER,
//     MSG_EXCHANGE
// };

// enum MSG_CMD
// {
//     SYS_PING,
//     SYS_PONG,
//     SYS_INFO,

//     ACCOUNT_IMPORT = 0,
//     ACCOUNT_TOP100,
//     ACCOUNT_PROBE,
//     ACCOUNT_QUERY,
//     ACCOUNT_HISTORY,
    
//     TX_CMD = 0,
    
//     BLOCK_SYNC = 0,

//     TOPIC_QUESTION_PROBE = 0,
//     TOPIC_DETAIL_PROBE,
//     TOPIC_LIST,
//     TOPIC_ANSWER_LIST,

//     EXPLORER_MAIN_PAGE = 0,
//     EXPLORER_NEXT_PAGE,
//     EXPLORER_BLOCK_PAGE,
//     EXPLORER_TX_PAGE,
//     EXPLORER_ACCOUNT_PAGE,
//     EXPLORER_QUERY,

//     EXCHANGE_LOGIN = 0,
//     EXCHANGE_NOTIFY_DEPOSIT,
//     EXCHANGE_DEPOSIT_TX_PROBE,
//     EXCHANGE_WITHDRAW_TX_PROBE
// };

// //..............................C++ Full-node websocket api error enum.............................
// enum EC
// {
//     ERR_TX_EXIST = 1,
//     ERR_PUBKEY_EXIST,
//     ERR_SIGN_EXPIRED,
//     ERR_REG_FAILED,
//     ERR_REG_WAIT,
//     ERR_TX_EXPIRED,
//     ERR_NAME_EXIST,
//     ERR_REFERRER_NOT_EXIST,
//     ERR_REFERRER_BALANCE_NOT_ENOUGH,
//     ERR_PUBKEY_NOT_REGISTERED,
//     ERR_BALANCE_NOT_ENOUGH,
//     ERR_RECEIVER_NOT_EXIST,
//     ERR_TOPIC_EXIST,
//     ERR_TOPIC_NUM_EXCEED_LIMIT,
//     ERR_TOPIC_NOT_EXIST,
//     ERR_REPLY_NOT_EXIST,
//     ERR_REPLY_NUM_EXCEED_LIMIT,
//     ERR_JOINED_TOPIC_NUM_EXCEED_LIMIT,
//     ERR_TOPIC_BALANCE_NOT_ENOUGH,
//     ERR_ACCOUNT_ID_NOT_EXIST,
//     ERR_ACCOUNT_NAME_NOT_MATCH,
//     ERR_TX_NOT_EXIST
// };

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

var latest_block_id = 0;
var pending_deposit_txs = {};
var pending_withdraw_txs = {};
var pre_pending_withdraw_txs = {};
var withdraw_unique_id = 0;

// users registered on your website
var your_user_list = ["user0", "user1", "user2", "user3", "user4", "user5", "user6", "user7", "user8", "user9"];
var balance_of_each_user = {};

for(var i = 0; i < your_user_list.length; ++i) {
    balance_of_each_user[your_user_list[i]] = 0;
}

function request_for_withdrawal(user_name, receiver_id, receiver_name, amount, memo)
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

    setInterval(function() {
        for(var name in balance_of_each_user) {
            console.log("balance_of_each_user[" + name + "]:", balance_of_each_user[name]);
        }
    }, 5000);
});

ws.on('error', function(err) {
    console.log("error happened: ", err);
    process.exit();
});

ws.on('close', function() {
    console.log("websocket closed");
    process.exit();
});

ws.on('message', function(msg_data) {
    var msg_obj = JSON.parse(msg_data);
    
    if(msg_obj.msg_type == 0 && msg_obj.msg_cmd == 1) // SYS_PONG
    {
        setTimeout(function() {
            ws.send(JSON.stringify({msg_type:0, msg_cmd:0, msg_id:0})); // SYS_PING
        }, 10000);
    }
    else if(msg_obj.msg_type == 3 && msg_obj.msg_cmd == 0) // BLOCK_SYNC
    {
        latest_block_id = msg_obj.block_id;
    }
    else if(msg_obj.msg_type == 1 && msg_obj.msg_cmd == 3) // ACCOUNT_QUERY
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
    }
    else if(msg_obj.msg_type == 6) // MSG_EXCHANGE
    {
        if(msg_obj.msg_cmd == 0) // EXCHANGE_LOGIN
        {
            latest_block_id = msg_obj.cur_block_id;

            // The main reason for this error is that consensus algorithm judges
            // the chain with the most cumulative difficulty as the main chain.
            // In the process of consensus, it is possible to abandon the current
            // branch chain many times and switch to a new main chain.
            // Usually, this error may occur only in a short time.
            if(msg_obj.err_code == 20) // ERR_ACCOUNT_ID_NOT_EXIST
            {
                console.log("account id not exist!");
                return;
            }
            
            // The main reason for this error is that consensus algorithm judges
            // the chain with the most cumulative difficulty as the main chain.
            // In the process of consensus, it is possible to abandon the current
            // branch chain many times and switch to a new main chain.
            // Usually, this error may occur only in a short time.
            if(msg_obj.err_code == 21) // ERR_ACCOUNT_NAME_NOT_MATCH
            {
                console.log("account name not match!");
                return;
            }
            
            if(msg_obj.err_code == null)
            {
                ws.send(JSON.stringify({msg_type:0, msg_cmd:0, msg_id:0})); // send ping message
            }
        }
        else if(msg_obj.msg_cmd == 1) // EXCHANGE_NOTIFY_DEPOSIT
        {
            if(pending_deposit_txs[msg_obj.tx_id] == null)
            {
                var deposit_info = {};
                deposit_info.block_id = msg_obj.block_id;
                deposit_info.block_hash = msg_obj.block_hash;
                deposit_info.utc = msg_obj.utc;
                deposit_info.tx_id = msg_obj.tx_id;
                deposit_info.sender_id = msg_obj.sender_id;
                deposit_info.sender_name = msg_obj.sender_name;
                deposit_info.amount = msg_obj.amount;
                deposit_info.memo = msg_obj.memo;
                setTimeout(function() {
                    // send EXCHANGE_DEPOSIT_TX_PROBE message
                    ws.send(JSON.stringify({
                        msg_type: 6,
                        msg_cmd: 2,
                        msg_id: 0,
                        block_id: deposit_info.block_id,
                        block_hash: deposit_info.block_hash,
                        tx_id: deposit_info.tx_id
                    }));
                }, 10000);
                pending_deposit_txs[msg_obj.tx_id] = deposit_info;
                console.log("recv notify of deposit:", deposit_info);
            }
            else
            {
                // only need to update the following 3 field
                var deposit_info = pending_deposit_txs[msg_obj.tx_id];
                deposit_info.block_id = msg_obj.block_id;
                deposit_info.block_hash = msg_obj.block_hash;
                deposit_info.utc = msg_obj.utc;
                console.log("recv notify of deposit(already exist):", deposit_info);
            }
        }
        else if(msg_obj.msg_cmd == 2) // EXCHANGE_DEPOSIT_TX_PROBE
        {
            latest_block_id = msg_obj.cur_block_id;
            var deposit_info = pending_deposit_txs[msg_obj.tx_id];
            
            // The main reason for this error is that consensus algorithm judges
            // the chain with the most cumulative difficulty as the main chain.
            // In the process of consensus, it is possible to abandon the current
            // branch chain many times and switch to a new main chain.
            // Usually, this error may occur only in a short time.
            if(msg_obj.err_code == 22) // ERR_TX_NOT_EXIST, 
            {
                console.log("tx id not exist:", msg_obj.tx_id);

                // try again
                setTimeout(function() {
                    // send EXCHANGE_DEPOSIT_TX_PROBE message
                    ws.send(JSON.stringify({
                        msg_type: 6,
                        msg_cmd: 2,
                        msg_id: 0,
                        block_id: deposit_info.block_id,
                        block_hash: deposit_info.block_hash,
                        tx_id: deposit_info.tx_id
                    }));
                }, 10000);
                return;
            }
            
            // only need to update the following 3 field
            deposit_info.block_id = msg_obj.block_id;
            deposit_info.block_hash = msg_obj.block_hash;
            deposit_info.utc = msg_obj.utc;
            var confirms = latest_block_id + 1 - deposit_info.block_id;
            console.log("deposit tx_id: %s, receive %d confirms from miner", msg_obj.tx_id, confirms);

            // We suggest that the user's balance of funds should
            // only be updated upon receipt of 100 confirmations
            if(confirms >= 100) {
                var receiver_b64 = deposit_info.memo;
                var buf = Buffer.from(receiver_b64, 'base64');
                var receiver = buf.toString();
                
                if(balance_of_each_user[receiver] != null) {
                    balance_of_each_user[receiver] += deposit_info.amount;
                }
                
                // delete from pending_deposit_txs
                pending_deposit_txs[msg_obj.tx_id] = null;
                return;
            }

            setTimeout(function() {
                // send EXCHANGE_DEPOSIT_TX_PROBE message
                ws.send(JSON.stringify({
                    msg_type: 6,
                    msg_cmd: 2,
                    msg_id: 0,
                    block_id: deposit_info.block_id,
                    block_hash: deposit_info.block_hash,
                    tx_id: deposit_info.tx_id
                }));
            }, 10000);
        }
        else if(msg_obj.msg_cmd == 3) // EXCHANGE_WITHDRAW_TX_PROBE
        {
            latest_block_id = msg_obj.cur_block_id;
            var withdraw_info = pending_withdraw_txs[msg_obj.tx_id];
            
            // The main reason for this error is that consensus algorithm judges
            // the chain with the most cumulative difficulty as the main chain.
            // In the process of consensus, it is possible to abandon the current
            // branch chain many times and switch to a new main chain.
            // Usually, this error may occur only in a short time.
            if(msg_obj.err_code == 22) // ERR_TX_NOT_EXIST, 
            {
                console.log("tx id not exist:", msg_obj.tx_id);

                // try again
                setTimeout(function() {
                    // send EXCHANGE_WITHDRAW_TX_PROBE message
                    ws.send(JSON.stringify({
                        msg_type: 6,
                        msg_cmd: 3,
                        msg_id: 0,
                        block_id: withdraw_info.block_id,
                        tx_id: withdraw_info.tx_id
                    }));
                }, 10000);
                return;
            }
            
            // only need to update the following 3 field
            withdraw_info.block_id = msg_obj.block_id;
            withdraw_info.block_hash = msg_obj.block_hash;
            withdraw_info.utc = msg_obj.utc;
            var confirms = latest_block_id + 1 - withdraw_info.block_id;
            console.log("withdraw tx_id: %s, receive %d confirms from miner", msg_obj.tx_id, confirms);

            // We suggest that the user's balance of funds should
            // only be updated upon receipt of 100 confirmations
            if(confirms >= 100) {
                var sender = withdraw_info.sender_name;

                if(balance_of_each_user[sender] != null) {
                    balance_of_each_user[sender] -= withdraw_info.amount;
                }
                
                // delete from pending_withdraw_txs
                pending_withdraw_txs[msg_obj.tx_id] = null;
                return;
            }
            
            setTimeout(function() {
                // send EXCHANGE_WITHDRAW_TX_PROBE message
                ws.send(JSON.stringify({
                    msg_type: 6,
                    msg_cmd: 3,
                    msg_id: 0,
                    block_id: withdraw_info.block_id,
                    tx_id: withdraw_info.tx_id
                }));
            }, 10000);
        }
    }
});

// // how to generate registration sign string
// var data_obj = {};
// data_obj.block_id = latest_block_id;
// data_obj.fee = 2;
// data_obj.name = Buffer.from("username").toString('base64');
// data_obj.referrer = 'BC9YHbvohhgCxA+8FbHbcJozcVKl0W9ltw3veDxzO066ulbmu19Hb4kY2OS3NnNmIDFNKSzh8fjl7u6KqcUoWQA='; // change to your pubkey
// var data_obj_hash_raw = hash.sha256().update(hash.sha256().update(JSON.stringify(data_obj)).digest()).digest();
// var sign = your_privkey.sign(data_obj_hash_raw).toDER();
// var sign_b64 = Buffer.from(sign).toString('base64');
// var sign_string = '{"sign":"' + sign_b64 + '","sign_data":' + JSON.stringify(data_obj) + '}';
// console.log("sign_string is:", sign_string);
// return;
