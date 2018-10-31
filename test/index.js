var hash = require('hash.js');
const { randomBytes } = require('crypto')
var EC = require('elliptic').ec;
var ec = new EC('secp256k1');
var WebSocket = require('ws');

// protocol:
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
//         "type":5,
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
//         "type":6,
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
//         "type":7,
//         "pubkey":"2fwfewefef",
//         "utc":9988888,
//         "block_id": 339,
//         "fee":98,
//         "topic_key":"lllllllllllllllllllllllllllllllll",
//         "reply_to":"ooooooooooiwiieiweo",
//         "amount":9222
//     }
// }


// //var ws = new WebSocket('ws://172.104.48.244:18051');
// var ws = new WebSocket('ws://192.168.0.122:19051');

// ws.on('open', function open() {
//     console.log("reccv open msg");
//     ws.send(JSON.stringify({msg_id: 22, msg_type:0, msg_cmd: 2}));
// });

// ws.on('error', function(e) {
//     console.log("error event....................", e);
// });

// ws.on('close', function(e) {
//     console.log("close event....................", e);
// });
 
// ws.on('message', function incoming(data) {
//     console.log("recv msg:");
//     console.log(data);
    
// });

// return;

console.log('----------------------------------------------');

var tx_data = '{\"type\":1,\"pubkey\":\"BCf32BSqhVpDy04kIpC59IT16yp77oAJnEBeRJZWc7I8JtYd2HlCtUJPPKSA4yea7dyWowXpGbaRpKoGD9Wy0mk=\",\"utc\":1540950124,\"avatar\":1,\"sign\":\"MEUCIQCjZolI48Sxgn5oWcljhfgiGpfnNRWF9fth3NbLWMjdKQIgXnHzKCDS3ErPyFIkgXfXSyYxOjObnnq9y/FakU2UpaU=\",\"sign_data\":{\"block_id\":1051,\"fee\":2,\"name\":\"dHN0MQ==\",\"referrer\":\"BH6PNUv9anrjG9GekAd+nus+emyYm1ClCT0gIut1O7A3w6uRl7dAihcD8HvKh+IpOopcgQAzkYxQZ+cxT+32WdM=\"}}';

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
