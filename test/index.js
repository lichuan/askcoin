var hash = require('hash.js');
var EC = require('elliptic').ec;
var ec = new EC('secp256k1');

while(true) {
var key = ec.genKeyPair();
var privstr = key.priv.toString(16, 2);
var priv2 = key.getPrivate("hex");
console.log(privstr, privstr.length, typeof privstr);
console.log(priv2, priv2.length, typeof priv2);
console.log(key, typeof key);


var res = hash.sha256().update('a1232323232342342bc').digest();
// var res = hash.ripemd160().update(hash.sha256().update('a1232323232342342bc').digest()).digest('hex');
// var res_256 = hash.sha256().update(hash.sha256().update('a1232323232342342bc').digest()).digest('hex');
// console.log("typeof res: ", typeof res, " typeof res_256: ", typeof res_256);
// console.log(res,res_256);
// console.log('hash:', res, typeof res, res.length);
// console.log('hash_256:', res_256, typeof res_256, res_256.length);


var sig = key.sign(res);
console.log('sig: ', sig, typeof sig);
sig = sig.toDER();
console.log('sig der:', sig, typeof sig, sig.length);
console.log(key.verify(res, sig), typeof sig);

console.log("pub.....................................");
var pub = key.getPublic('hex');
console.log(pub, typeof pub, pub.length);

var key = ec.keyFromPublic(pub, 'hex');
console.log("pub end.............................");

console.log(key.verify(res, sig));

if(privstr.startsWith('0')) {
    break;
}



    var bf = new Buffer(pub, 'hex');
    //console.log("buf: ", bf);
    var lcres = hash.sha256().update(bf).digest();
    console.log("lcres: ", lcres, typeof lcres);
    var bf2 = new Buffer(res);
    console.log("lcres2: ", bf2.toString('base64'));


    
    break;
    
    }




var ec = new EC('secp256k1');

var pub2 = "04889eedad4977924cce46baac49e6e58bac17cf7a6eca04da051fcf81cfa896cf093f11c13ff22071b6a58b514df904ce00510f1232c9ba942c0e4218324d8afc";
var pub2_buf = Buffer(pub2, 'hex').toString('base64');
console.log("pub2_buf: ", pub2_buf);

privstr = 'd5c7719843f730eb4712bad2d6b60e4315b39affdf814b27ffe86f95e808304';
var key2 = ec.keyFromPrivate(privstr, 'hex');
console.log(key2, typeof key2);
var sig = key2.sign(res);
sig = sig.toDER();
console.log('sig2: ', sig, typeof sig, sig.length);
var sig2_buf = new Buffer(sig).toString('base64');
console.log("sig2_buf: ", sig2_buf, sig2_buf.length);

//console.log('sig2 der: ', sig, typeof sig, sig.length);
console.log(key2.verify(res, sig));

var pub = key2.getPublic('hex');
console.log(pub, typeof pub);

var key = ec.keyFromPublic(pub, 'hex');
console.log(key.verify(res, sig));

