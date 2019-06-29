var hash = require('hash.js');
const { randomBytes } = require('crypto')
var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var WebSocket = require('ws');
var crypto = require('crypto');

//..............................protocol.............................

// enum MSG_TYPE
// {
//     MSG_SYS,
//     MSG_ACCOUNT,
//     MSG_TX,
//     MSG_BLOCK,
// };

// enum MSG_CMD
// {
//     SYS_PING,
//     SYS_PONG,
//     SYS_INFO,

//     ACCOUNT_IMPORT = 0,
//     ACCOUNT_TOP100,
    
//     TX_CMD = 0,
    
//     BLOCK_SYNC = 0
// };

// {"msg_type":2,"msg_cmd":3,"msg_id":1,"sign":"tx sign data","data":{}}

// tx register account
// {
//     "sign":"oijowwwwwwwww",
//     "data":{
//         "type":1,
//         "pubkey":"eeeeeeeeeee",
//         "utc":9988888,
//         "avatar":22,
//         "sign":"awfwewewdffff",
//         "sign_data": {
//             "block_id":9283,
//             "fee":100000000,
//             "name":"b64(iijjjj中文)",
//             "referrer":"pubkey......."
//         }
//     }
// }

// tx sendcoin
// {
//     "sign":"oijowwwwwwwww",
//     "data":{
//         "type":2,
//         "pubkey":"oikkkkkkkkkk",
//         "utc": 2989883883,
//         "block_id": 339,
//         "fee":2000022,
//         "amount": 10000000,
//         "memo":"this is my memo msg",
//         "receiver":"pubkey........"
//     }
// }

// tx new topic
// {
//     "sign":"oijowwwwwwwww",
//     "data":{
//         "type":3,
//         "pubkey":"oikkkkkkkkkk",
//         "utc":9988888,
//         "block_id": 339,
//         "fee":2222,
//         "reward":9999,
//         "topic":"abceffabbbb323233232323"
//     }
// }

// tx topic reply
// {
//     "sign":"oijowwwwwwwww",
//     "data":{
//         "type":4,
//         "pubkey":"eeeeeeeeee",
//         "utc":9988888,
//         "block_id": 339,
//         "fee":332,
//         "topic_key":"lllllllllllllllllllllllllllllllll",
//         "reply":"abceffabbbb323233232323",
//         "reply_to":"to key..."
//     }
// }

// tx give reward
// {
//     "sign":"oijowwwwwwwww",
//     "data":{
//         "type":5,
//         "pubkey":"2fwfewefef",
//         "utc":9988888,
//         "block_id": 339,
//         "fee":98,
//         "topic_key":"lllllllllllllllllllllllllllllllll",
//         "reply_to":"ooooooooooiwiieiweo",
//         "amount":9222
//     }
// }

//...................................crypto library.................................
var tx_data = "{\"type\":1,\"pubkey\":\"BCf32BSqhVpDy04kIpC59IT16yp77oAJnEBeRJZWc7I8JtYd2HlCtUJPPKSA4yea7dyWowXpGbaRpKoGD9Wy0mk=\",\"utc\":1540950124,\"avatar\":1,\"sign\":\"MEUCIQCjZolI48Sxgn5oWcljhfgiGpfnNRWF9fth3NbLWMjdKQIgXnHzKCDS3ErPyFIkgXfXSyYxOjObnnq9y/FakU2UpaU=\",\"sign_data\":{\"block_id\":1051,\"fee\":2,\"name\":\"dHN0MQ==\",\"referrer\":\"BH6PNUv9anrjG9GekAd+nus+emyYm1ClCT0gIut1O7A3w6uRl7dAihcD8HvKh+IpOopcgQAzkYxQZ+cxT+32WdM=\"}}";

var hash_raw = hash.sha256().update(hash.sha256().update(tx_data).digest()).digest();
var hash_b64 = Buffer.from(hash_raw).toString('base64');
console.log("hash:", hash_b64);

var privkey_buf = Buffer.from("Vm1wSmQwMVhSWGxUYTJScVUwWktXRmxzVWtKaVJUQjN=", 'base64');
var privkey = ec.keyFromPrivate(privkey_buf);
var sign = privkey.sign(hash_raw).toDER();
var sign_b64 = Buffer.from(sign).toString('base64');
console.log("sign:", sign_b64);

var pubkey_hex = privkey.getPublic('hex');
var pubkey_b64 = Buffer.from(pubkey_hex, 'hex').toString('base64');
console.log("pubkey:", pubkey_b64);

var pubkey = ec.keyFromPublic(pubkey_hex, 'hex');

if(pubkey.verify(hash_raw, sign))
{
    console.log("verify sign successfully");
}

// generate
var key_pair = ec.genKeyPair();
var privkey_hex = key_pair.getPrivate("hex");
var privkey = ec.keyFromPrivate(privkey_hex, 'hex');
var pubkey_hex = privkey.getPublic('hex');
var pubkey = ec.keyFromPublic(pubkey_hex, 'hex');
var privkey_b64 = Buffer.from(privkey_hex, 'hex').toString('base64');
var pubkey_b64 = Buffer.from(pubkey_hex, 'hex').toString('base64');
console.log("generate new privkey:", privkey_b64);
console.log("generate new pubkey:", pubkey_b64);

// test new privkey and pubkey
var sign = privkey.sign(hash_raw).toDER();
var sign_b64 = Buffer.from(sign).toString('base64');
console.log("sign:", sign_b64);

if(pubkey.verify(hash_raw, sign))
{
    console.log("new pubkey verify sign successfully");
}

//...............................wsock...............................
var ws = new WebSocket('ws://192.168.0.127:19050');
var ping_timer;

ws.on('open', function open() {
    console.log("recv open msg..................");

    // send ping packet
    ping_timer = setInterval(function() {
        ws.send(JSON.stringify({msg_type:0, msg_cmd:0, msg_id:1}));
    }, 10000);

    // get info from server
    ws.send(JSON.stringify({msg_type:0, msg_cmd:2, msg_id:100}));
    
    var HF_1_BLOCK_ID = 500000;

    // register account, need generate privkey
    var key_pair = ec.genKeyPair();
    var privkey_hex = key_pair.getPrivate("hex");
    var privkey = ec.keyFromPrivate(privkey_hex, 'hex');
    var pubkey_hex = privkey.getPublic('hex');
    var pubkey = ec.keyFromPublic(pubkey_hex, 'hex');
    var privkey_b64 = Buffer.from(privkey_hex, 'hex').toString('base64');
    var pubkey_b64 = Buffer.from(pubkey_hex, 'hex').toString('base64');
    var data_obj = {};
    data_obj.type = 1;
    data_obj.pubkey = pubkey_b64;
    var utc = (Date.now() / 1000);
    data_obj.utc = parseInt(utc);
    data_obj.avatar = 3;
    var sign_str = '{"sign":"MEUCIQCyU/J+rqjF6ZxTyZ7ZgmQ5hC/F4hEA0mtWGbzjZHFBBgIgfjA9stVN7MhI3esIZJ3mPHwcjgrZThNmPshLv5UnfVQ=","sign_data":{"block_id":1405,"fee":2,"name":"YWNjb3VudF8x","referrer":"BKBWkg5g5H0YBSqT1U0/aT/s1czat6SObFafhbpbsgvY9SO4k81Ay9jkq3zKRkXwSAA4BNmu8T+GjuUnXM4raLU="}}';
    var sign_obj = JSON.parse(sign_str);
    data_obj.sign = sign_obj.sign;
    data_obj.sign_data = sign_obj.sign_data;
    var tx_hash_raw = hash.sha256().update(hash.sha256().update(JSON.stringify(data_obj)).digest()).digest();
    var tx_buf = Buffer.from(tx_hash_raw);
    
    // first hardfork block height
    if(sign_obj.sign_data.block_id >= HF_1_BLOCK_ID) {
        // write block_id in the tx, big-endian
        tx_buf.writeUInt32BE(sign_obj.sign_data.block_id, tx_buf.length - 4);
        tx_buf = Buffer.concat([tx_buf, Buffer.alloc(1)]);
        tx_buf[32] = 19; // add 'T' at the end of tx_id
    }
    
    var tx_id = tx_buf.toString('base64');
    var sign = privkey.sign(tx_hash_raw).toDER();
    var sign_b64 = Buffer.from(sign).toString('base64');
    var packet = {msg_type:2, msg_cmd:0, msg_id:1, sign:sign_b64, data:data_obj};
    console.log(JSON.stringify(packet));
    ws.send(JSON.stringify(packet));
    
    // privkey come from import
    var privkey_buf = Buffer.from("Vm1wSmQwMVhSWGxUYTJScVUwWktXRmxzVWtKaVJUQjN=", 'base64');
    var privkey = ec.keyFromPrivate(privkey_buf);
    var pubkey_hex = privkey.getPublic('hex');
    var pubkey_b64 = Buffer.from(pubkey_hex, 'hex').toString('base64');
    
    // import account msg
    var data_obj = {};
    data_obj.utc = parseInt(Date.now() / 1000);
    data_obj.pubkey = pubkey_b64;
    var tx_hash_raw = hash.sha256().update(hash.sha256().update(JSON.stringify(data_obj)).digest()).digest();
    var sign = privkey.sign(tx_hash_raw).toDER();
    var sign_b64 = Buffer.from(sign).toString('base64');
    ws.send(JSON.stringify({msg_type:1, msg_cmd:0, msg_id:2, sign:sign_b64, data:data_obj}));

    // sendcoin
    var data_obj = {};
    data_obj.type = 2;
    data_obj.pubkey = pubkey_b64;
    var utc = (Date.now() / 1000);
    data_obj.utc = parseInt(utc);
    data_obj.block_id = 1500;
    data_obj.fee = 2;
    data_obj.amount = 100;
    data_obj.memo = Buffer.from("this is memo data").toString('base64');
    data_obj.receiver = "BAlgyYbC43fc7brIieAc1yKMSsO12ElINyeF9PyjKOgljkkOK1B8fEgRVOP6kGsOwx4X5lGwtkIrSHJttpqWzSM=";
    var tx_hash_raw = hash.sha256().update(hash.sha256().update(JSON.stringify(data_obj)).digest()).digest();
    var tx_buf = Buffer.from(tx_hash_raw);
    
    // first hardfork block height
    if(data_obj.block_id >= HF_1_BLOCK_ID) {
        // write block_id in the tx, big-endian
        tx_buf.writeUInt32BE(data_obj.block_id, tx_buf.length - 4);
        tx_buf = Buffer.concat([tx_buf, Buffer.alloc(1)]);
        tx_buf[32] = 19; // add 'T' at the end of tx_id
    }
    
    var tx_id = tx_buf.toString('base64');
    var sign = privkey.sign(tx_hash_raw).toDER();
    var sign_b64 = Buffer.from(sign).toString('base64');
    var packet = {msg_type:2, msg_cmd:0, msg_id:2, sign:sign_b64, data:data_obj};
    console.log(JSON.stringify(packet));
    ws.send(JSON.stringify(packet));
    
    // new topic
    var data_obj = {};
    data_obj.type = 3;
    data_obj.pubkey = pubkey_b64;
    var utc = (Date.now() / 1000);
    data_obj.utc = parseInt(utc);
    data_obj.block_id = 1500;
    data_obj.fee = 2;
    data_obj.reward = 100;
    data_obj.topic = Buffer.from("this topic data is 中文内容也可以，一共300字节最多，不能超出 问题的描述 questionnnnnnnnnnnnnnnnnnnn").toString('base64');
    var tx_hash_raw = hash.sha256().update(hash.sha256().update(JSON.stringify(data_obj)).digest()).digest();
    var tx_buf = Buffer.from(tx_hash_raw);
    
    // first hardfork block height
    if(data_obj.block_id >= HF_1_BLOCK_ID) {
        // write block_id in the tx, big-endian
        tx_buf.writeUInt32BE(data_obj.block_id, tx_buf.length - 4);
        tx_buf = Buffer.concat([tx_buf, Buffer.alloc(1)]);
        tx_buf[32] = 19; // add 'T' at the end of tx_id
    }
    
    var tx_id = tx_buf.toString('base64');
    var sign = privkey.sign(tx_hash_raw).toDER();
    var sign_b64 = Buffer.from(sign).toString('base64');
    var packet = {msg_type:2, msg_cmd:0, msg_id:2, sign:sign_b64, data:data_obj};
    console.log(JSON.stringify(packet));
    console.log("tx_id:", tx_id);
    ws.send(JSON.stringify(packet));

    // topic reply
    var data_obj = {};
    data_obj.type = 4;
    data_obj.pubkey = pubkey_b64;
    var utc = (Date.now() / 1000);
    data_obj.utc = parseInt(utc);
    data_obj.block_id = 1500;
    data_obj.fee = 2;
    data_obj.topic_key = "R/F/I+BQ+yuU9CWDDzLbA45tMtv8Ld16VfzW0MdbSV8=";
    data_obj.reply = Buffer.from("this topic reply 回复 replyyyyyyyyyyyyyyyyyyyyyyyyy").toString('base64');
    var tx_hash_raw = hash.sha256().update(hash.sha256().update(JSON.stringify(data_obj)).digest()).digest();
    var tx_buf = Buffer.from(tx_hash_raw);
    
    // first hardfork block height
    if(data_obj.block_id >= HF_1_BLOCK_ID) {
        // write block_id in the tx, big-endian
        tx_buf.writeUInt32BE(data_obj.block_id, tx_buf.length - 4);
        tx_buf = Buffer.concat([tx_buf, Buffer.alloc(1)]);
        tx_buf[32] = 19; // add 'T' at the end of tx_id
    }
    
    var tx_id = tx_buf.toString('base64');
    var sign = privkey.sign(tx_hash_raw).toDER();
    var sign_b64 = Buffer.from(sign).toString('base64');
    var packet = {msg_type:2, msg_cmd:0, msg_id:2, sign:sign_b64, data:data_obj};
    console.log(JSON.stringify(packet));
    console.log("tx_id:", tx_id);
    ws.send(JSON.stringify(packet));

    // give reward
    var data_obj = {};
    data_obj.type = 5;
    data_obj.pubkey = pubkey_b64;
    var utc = (Date.now() / 1000);
    data_obj.utc = parseInt(utc);
    data_obj.block_id = 1900;
    data_obj.fee = 2;
    data_obj.topic_key = "R/F/I+BQ+yuU9CWDDzLbA45tMtv8Ld16VfzW0MdbSV8=";
    data_obj.reply_to = "rLIcxNNqocIfMgTXADE6dupysw5skfTwxdjMbHHLAJg=";
    data_obj.amount = 10;
    var tx_hash_raw = hash.sha256().update(hash.sha256().update(JSON.stringify(data_obj)).digest()).digest();
    var tx_buf = Buffer.from(tx_hash_raw);
    
    // first hardfork block height
    if(data_obj.block_id >= HF_1_BLOCK_ID) {
        // write block_id in the tx, big-endian
        tx_buf.writeUInt32BE(data_obj.block_id, tx_buf.length - 4);
        tx_buf = Buffer.concat([tx_buf, Buffer.alloc(1)]);
        tx_buf[32] = 19; // add 'T' at the end of tx_id
    }
    
    var tx_id = tx_buf.toString('base64');
    var sign = privkey.sign(tx_hash_raw).toDER();
    var sign_b64 = Buffer.from(sign).toString('base64');
    var packet = {msg_type:2, msg_cmd:0, msg_id:2, sign:sign_b64, data:data_obj};
    console.log(JSON.stringify(packet));
    console.log("tx_id:", tx_id);
    ws.send(JSON.stringify(packet));
});

ws.on('error', function(e) {
    console.log("error event....................", e);
});

ws.on('close', function(e) {
    clearInterval(ping_timer);
    console.log("close event....................", e);
});
 
ws.on('message', function incoming(data) {
    console.log("recv msg..............");
    console.log(data);
});
