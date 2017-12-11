var hash = require('hash.js');
var EC = require('elliptic').ec;
var ec = new EC('secp256k1');

var key = ec.genKeyPair();
var privstr = key.priv.toString(16);
console.log(privstr, privstr.length);
console.log(key, typeof privstr);


//var res = hash.sha256().update('a1232323232342342bc').digest('hex');
var res = hash.ripemd160().update(hash.sha256().update('a1232323232342342bc').digest()).digest();
var bf = new Buffer(res);
res = bf.toString('base64');
console.log('hash:', res, typeof res, res.length);
return;

var sig = key.sign(res);
console.log('sig: ', sig, typeof sig);
sig = sig.toDER();
console.log('sig der:', sig, typeof sig, sig.length);
console.log(key.verify(res, sig), typeof sig);

var pub = key.getPublic();
console.log(pub, typeof pub);

console.log(pub.encode('hex'));
var key = ec.keyFromPublic(pub);
console.log(key.verify(res, sig));


var ec = new EC('secp256k1');
privstr = 'd48215c1dff99f546914af794fa47861ddf7f10e25a10bdb49a177f6dd93221d';
var key2 = ec.keyFromPrivate(privstr);
console.log(key2, typeof key2);
var sig = key2.sign(res);
console.log('sig2: ', sig, typeof sig);
sig = sig.toDER();
//console.log('sig2 der: ', sig, typeof sig, sig.length);
console.log(key2.verify(res, sig));

var pub = key2.getPublic();
console.log(pub, typeof pub);

console.log(pub.encode('hex'));
var key = ec.keyFromPublic(pub);
console.log(key.verify(res, sig));

