// Depends on jsbn.js and rng.js
// Version 1.1: support utf-8 encoding in pkcs1pad2
// convert a (hex) string to a bignum object


function parseBigInt(str, r)
{
    return new BigInteger(str, r);
}

function linebrk(s, n)
{
    var ret = "";
    var i = 0;
    while (i + n < s.length)
    {
        ret += s.substring(i, i + n) + "\n";
        i += n;
    }
    return ret + s.substring(i, s.length);
}

function byte2Hex(b)
{
    if (b < 0x10) return "0" + b.toString(16);
    else return b.toString(16);
}

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint


function pkcs1pad2(s, n)
{
    if (n < s.length + 11)
    { // TODO: fix for utf-8
        //alert("Message too long for RSA (n=" + n + ", l=" + s.length + ")");
        //return null;
        throw "Message too long for RSA (n=" + n + ", l=" + s.length + ")";
    }
    var ba = new Array();
    var i = s.length - 1;
    while (i >= 0 && n > 0)
    {
        var c = s.charCodeAt(i--);
        if (c < 128)
        { // encode using utf-8
            ba[--n] = c;
        }
        else if ((c > 127) && (c < 2048))
        {
            ba[--n] = (c & 63) | 128;
            ba[--n] = (c >> 6) | 192;
        }
        else
        {
            ba[--n] = (c & 63) | 128;
            ba[--n] = ((c >> 6) & 63) | 128;
            ba[--n] = (c >> 12) | 224;
        }
    }
    ba[--n] = 0;
    var rng = new SecureRandom();
    var x = new Array();
    while (n > 2)
    { // random non-zero pad
        x[0] = 0;
        while (x[0] == 0) rng.nextBytes(x);
        ba[--n] = x[0];
    }
    ba[--n] = 2;
    ba[--n] = 0;
    return new BigInteger(ba);
}

// "empty" RSA key constructor


function RSAKey()
{
    this.n = null;
    this.e = 0;
    this.d = null;
    this.p = null;
    this.q = null;
    this.dmp1 = null;
    this.dmq1 = null;
    this.coeff = null;
}
// Set the public key fields N and e from hex strings


function RSASetPublic(N, E)
{
    if (N != null && E != null && N.length > 0 && E.length > 0)
    {
        this.n = parseBigInt(N, 16);
        this.e = parseInt(E, 16);
    }
    else alert("Invalid RSA public key");
}

// Perform raw public operation on "x": return x^e (mod n)


function RSADoPublic(x)
{
    return x.modPowInt(this.e, this.n);
}

// Return the PKCS#1 RSA encryption of "text" as an even-length hex string

function RSAEncrypt(text)
{
    var m = pkcs1pad2(text, (this.n.bitLength() + 7) >> 3);
    if (m == null) return null;
    var c = this.doPublic(m);
    if (c == null) return null;
    var h = c.toString(16);
    if ((h.length & 1) == 0) return h;
    else return "0" + h;
}


// Return RSA public and private key in PEM format. Added by fi1ingcabinet

function RSAKeyOut(RSAKey){
    
    //
    //VERSION
    //
    //02=INTEGER, 01=length is 1 byte, 00 is the version
    version = "020100"
    
    //
    //n
    //
    n = RSAKey.n.toString(16);
    //add a pad if the first bit is a 1
    if (['a', 'b', 'c', 'd', 'e', 'f', '9', '8'].indexOf(n.charAt(0)) >= 0) {
        n2 = "00" +n;
        }
    else {
        n2=n;
    }
    n3 = (n2.length)/2;
    //construct prefix for n
    prefix_n = prefix_int(n3);
    //construct prefix + n
    n_final = prefix_n + n2;
    console.log(n_final);
    
    //
    //e
    //
    e = RSAKey.e.toString(16);
    //pad if single value
    if (e.length % 2 == 1){
            e = "0"+e;
        }
    e2 = (e.length)/2;
    //construct prefix for p
    prefix_e = prefix_int(e2);
    //construct prefix + e
    e_final = prefix_e + e;
    
    //
    //d
    //
    d = RSAKey.d.toString(16);
    //add pad if first bit 1
    if (['a', 'b', 'c', 'd', 'e', 'f', '9', '8'].indexOf(d.charAt(0)) >= 0) {
        d2 = "00" +d;
        }
    else {
        d2=d;
    }
    d3 = (d2.length)/2;
    //construct prefix for p
    prefix_d = prefix_int(d3);
    //construct prefix + d
    d_final = prefix_d + d2;
    
    //
    //p
    //
    p = RSAKey.p.toString(16);
    //add pad if first bit 1
    if (['a', 'b', 'c', 'd', 'e', 'f', '9', '8'].indexOf(p.charAt(0)) >= 0) {
        p2 = "00" +p;
        }
    else {
        p2=p;
    }
    p3 = (p2.length)/2;
    //construct prefix for p
    prefix_p = prefix_int(p3);
    //construct prefix + p
    p_final = prefix_p + p2;
    
    //
    //q
    //
    q = RSAKey.q.toString(16);
    //add pad if first bit 1
    if (['a', 'b', 'c', 'd', 'e', 'f', '9', '8'].indexOf(q.charAt(0)) >= 0) {
        q2 = "00" +q;
        }
    else {
        q2=q;
    }
    q3 = (q2.length)/2;
    //construct prefix for q
    prefix_q = prefix_int(q3);
    //construct prefix + q
    q_final = prefix_q + q2;
    
    //
    //dmp1
    //
    dmp1 = RSAKey.dmp1.toString(16);
    //add pad if first bit 1
    if (['a', 'b', 'c', 'd', 'e', 'f', '9', '8'].indexOf(dmp1.charAt(0)) >= 0) {
        dmp12 = "00" +dmp1;
        }
    else {
        dmp12=dmp1;
    }
    dmp13 = (dmp12.length)/2;
    //construct prefix for dmp1
    prefix_dmp1 = prefix_int(dmp13);
    //construct prefix + dmp1
    dmp1_final = prefix_dmp1 + dmp12;
    
    //
    //dmq1
    //
    dmq1 = RSAKey.dmq1.toString(16);
    //add pad if first bit 1
    if (['a', 'b', 'c', 'd', 'e', 'f', '9', '8'].indexOf(dmq1.charAt(0)) >= 0) {
        dmq12 = "00" +dmq1;
        }
    else {
        dmq12=dmq1;
    }
    dmq13 = (dmq1.length)/2;
    //construct prefix for dmq1
    prefix_dmq1 = prefix_int(dmq13);
    //construct prefix + dmq1
    dmq1_final = prefix_dmq1 + dmq1;    
    
    //
    //coeff
    //
    coeff = RSAKey.coeff.toString(16);
    //pad if single value
    if (coeff.length % 2 == 1){
            coeff = "0"+coeff;
        }
    //add pad if first bit 1
    if (['a', 'b', 'c', 'd', 'e', 'f', '9', '8'].indexOf(coeff.charAt(0)) >= 0) {
        coeff2 = "00" +coeff;
        }
    else {
        coeff2=coeff;
    }
    coeff3 = (coeff2.length)/2;
    //construct prefix for coeff
    prefix_coeff = prefix_int(coeff3);
    //construct prefix + coeff
    coeff_final = prefix_coeff + coeff2;
    
    //
    //get the private key
    //
    private_key=""

    //total header
    head_1 = "30";
    total_content = version + n_final + e_final + d_final + p_final + q_final + dmp1_final + dmq1_final + coeff_final;
    total_length = (total_content.length)/2;
    total_length_byte = prefix_int(total_length).substring(2,);
    total_head = head_1 + total_length_byte;
    private_key = total_head + total_content;
    
    
    //
    //get the public key
    //
    public_key=""
    //total header
    head_1 = "30";
    total_content = n_final + e_final;
    total_length = (total_content.length)/2;
    total_length_byte = prefix_int(total_length).substring(2,);
    total_head = head_1 + total_length_byte;
    public_key_1 = total_head + total_content;
    head_2 = "00" + public_key_1;
    head_2_length = (head_2.length)/2;
    head_3 = "03" + prefix_int(head_2_length).substring(2,) + head_2;
    head_4 = "300d06092a864886f70d0101010500" + head_3;    
    head_4_length = (head_4.length)/2;
    head_5 = "30" + prefix_int(head_4_length).substring(2,) + head_4;
    public_key = head_5;
       
    return {private_key, public_key};

}
    

// function to add ASN.1 prefixes

function prefix_int(k){
    //if length of contents is < 127 the second byte is the length
    if (k<127){
        length_byte = k.toString(16)
        //if it is only one character (i.e. 1-16 in decimal) long, it requires a pad
        if (length_byte.length % 2 == 1){
            length_byte = "0"+length_byte;
        }
        //add the INTEGER prefix
        prefix = "02" + length_byte;
        return prefix
    }
    if (127 < k ){
        //work out how many bytes we need to use
        if ( (k/256)>=1 ){
            num_bytes = 2;
        }
        else {
            num_bytes = 1;
        }
        //length_byte is the length byte encoded
        len = 128 + num_bytes;
        length_byte = len.toString(16);
        //encode the value of the length
        hex_bytes = k.toString(16);        
        if (hex_bytes.length % 2 == 1){
            hex_bytes = "0"+hex_bytes;
        }
        //add the INTEGER prefix
        prefix = "02" + length_byte + hex_bytes;        
        return prefix;
    }
}

// function to split every 64 characters for log added by fi1ingcabinet from https://stackoverflow.com/questions/4321500/how-to-insert-a-newline-character-after-every-200-characters-with-jquery
function split64(str) {
  var result = '';
  while (str.length > 0) {
    result += str.substring(0, 64) + '\n';
    str = str.substring(64);
  }
  return result;
}

// function to split every 64 characters for HTML added by fi1ingcabinet from https://stackoverflow.com/questions/4321500/how-to-insert-a-newline-character-after-every-200-characters-with-jquery
function split64_html(str) {
  var result = '';
  while (str.length > 0) {
    result += str.substring(0, 64) + '<br>';
    str = str.substring(64);
  }
  return result;
}

// Function to add prefix and endfix in log added by fi1ingcabinet
function add_pem(str){
    
    pem_key = "-----BEGIN RSA PRIVATE KEY-----" + "\n" + str + "-----END RSA PRIVATE KEY-----";
    
    return pem_key;
}

// Function to add prefix and endfix in HTML added by fi1ingcabinet
function add_pem_html(str){
    
    pem_key = "-----BEGIN RSA PRIVATE KEY-----" + "<br>" + str + "-----END RSA PRIVATE KEY-----";
    
    return pem_key;
}

// copied from elsewhere
function base16tobase64(h) {
    var i;
    var base64Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var c;
    var ret = "";
    if(h.length % 2 == 1)
    {
        h = "0" + h;
    }
    for (i = 0; i + 3 <= h.length; i += 3)
    {
        c = parseInt(h.substring(i, i + 3), 16);
        ret += base64Chars.charAt(c >> 6) + base64Chars.charAt(c & 63);
    }
    if (i + 1 == h.length)
    {
        c = parseInt(h.substring(i, i + 1), 16);
        ret += base64Chars.charAt(c << 2);
    }
    else if (i + 2 == h.length)
    {
        c = parseInt(h.substring(i, i + 2), 16);
        ret += base64Chars.charAt(c >> 2) + base64Chars.charAt((c & 3) << 4);
    }
    while ((ret.length & 3) > 0) ret += "=";
    return ret;
}





// Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
//function RSAEncryptB64(text) {
//  var h = this.encrypt(text);
//  if(h) return hex2b64(h); else return null;
//}
// protected
RSAKey.prototype.doPublic = RSADoPublic;

// public
RSAKey.prototype.setPublic = RSASetPublic;
RSAKey.prototype.encrypt = RSAEncrypt;

// Version 1.1: support utf-8 decoding in pkcs1unpad2
// Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext

function pkcs1unpad2(d, n)
{
    var b = d.toByteArray();
    var i = 0;
    while (i < b.length && b[i] == 0)++i;
    if (b.length - i != n - 1 || b[i] != 2) return null;
    ++i;
    while (b[i] != 0)
    if (++i >= b.length) return null;
    var ret = "";
    while (++i < b.length)
    {
        var c = b[i] & 255;
        if (c < 128)
        { // utf-8 decode
            ret += String.fromCharCode(c);
        }
        else if ((c > 191) && (c < 224))
        {
            ret += String.fromCharCode(((c & 31) << 6) | (b[i + 1] & 63));
            ++i;
        }
        else
        {
            ret += String.fromCharCode(((c & 15) << 12) | ((b[i + 1] & 63) << 6) | (b[i + 2] & 63));
            i += 2;
        }
    }
    return ret;
}

// Set the private key fields N, e, and d from hex strings
function RSASetPrivate(N, E, D)
{
    if (N != null && E != null && N.length > 0 && E.length > 0)
    {
        this.n = parseBigInt(N, 16);
        this.e = parseInt(E, 16);
        this.d = parseBigInt(D, 16);
    }
    else alert("Invalid RSA private key");
}

// Set the private key fields N, e, d and CRT params from hex strings
function RSASetPrivateEx(N, E, D, P, Q, DP, DQ, C)
{
    if (N != null && E != null && N.length > 0 && E.length > 0)
    {
        this.n = parseBigInt(N, 16);
        this.e = parseInt(E, 16);
        this.d = parseBigInt(D, 16);
        this.p = parseBigInt(P, 16);
        this.q = parseBigInt(Q, 16);
        this.dmp1 = parseBigInt(DP, 16);
        this.dmq1 = parseBigInt(DQ, 16);
        this.coeff = parseBigInt(C, 16);
    }
    else alert("Invalid RSA private key");
}

// Generate a new random private key B bits long, using public expt E
function RSAGenerate(B, E)
{
    var rng = new SeededRandom();
    var qs = B >> 1;
    this.e = parseInt(E, 16);
    var ee = new BigInteger(E, 16);
    for (;;)
    {
        for (;;)
        {
            this.p = new BigInteger(B - qs, 1, rng);
            if (this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) break;
        }
        for (;;)
        {
            this.q = new BigInteger(qs, 1, rng);
            if (this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) break;
        }
        if (this.p.compareTo(this.q) <= 0)
        {
            var t = this.p;
            this.p = this.q;
            this.q = t;
        }
        var p1 = this.p.subtract(BigInteger.ONE);
        var q1 = this.q.subtract(BigInteger.ONE);
        var phi = p1.multiply(q1);
        if (phi.gcd(ee).compareTo(BigInteger.ONE) == 0)
        {
            this.n = this.p.multiply(this.q);
            this.d = ee.modInverse(phi);
            this.dmp1 = this.d.mod(p1);
            this.dmq1 = this.d.mod(q1);
            this.coeff = this.q.modInverse(this.p);
            break;
        }
    }
}

// Perform raw private operation on "x": return x^d (mod n)
function RSADoPrivate(x)
{
    if (this.p == null || this.q == null) return x.modPow(this.d, this.n);
    // TODO: re-calculate any missing CRT params
    var xp = x.mod(this.p).modPow(this.dmp1, this.p);
    var xq = x.mod(this.q).modPow(this.dmq1, this.q);
    while (xp.compareTo(xq) < 0)
    xp = xp.add(this.p);
    return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
}

// Return the PKCS#1 RSA decryption of "ctext".
// "ctext" is an even-length hex string and the output is a plain string.
function RSADecrypt(ctext)
{
    var c = parseBigInt(ctext, 16);
    var m = this.doPrivate(c);
    if (m == null) return null;
    return pkcs1unpad2(m, (this.n.bitLength() + 7) >> 3);
}

// protected
RSAKey.prototype.doPrivate = RSADoPrivate;

// public
RSAKey.prototype.setPrivate = RSASetPrivate;
RSAKey.prototype.setPrivateEx = RSASetPrivateEx;
RSAKey.prototype.generate = RSAGenerate;
RSAKey.prototype.decrypt = RSADecrypt;


//
// rsa-sign.js - adding signing functions to RSAKey class.
//
//
// version: 1.0 (2010-Jun-03)
//
// Copyright (c) 2010 Kenji Urushima (kenji.urushima@gmail.com)
//
// This software is licensed under the terms of the MIT License.
// http://www.opensource.org/licenses/mit-license.php
//
// The above copyright and license notice shall be 
// included in all copies or substantial portions of the Software.
//
// Depends on:
//   function sha1.hex(s) of sha1.js
//   jsbn.js
//   jsbn2.js
//   rsa.js
//   rsa2.js
//
// keysize / pmstrlen
//  512 /  128
// 1024 /  256
// 2048 /  512
// 4096 / 1024
// As for _RSASGIN_DIHEAD values for each hash algorithm, see PKCS#1 v2.1 spec (p38).
var _RSASIGN_DIHEAD = [];
_RSASIGN_DIHEAD['sha1'] = "3021300906052b0e03021a05000414";
_RSASIGN_DIHEAD['sha256'] = "3031300d060960864801650304020105000420";
//_RSASIGN_DIHEAD['md2'] = "3020300c06082a864886f70d020205000410";
//_RSASIGN_DIHEAD['md5'] = "3020300c06082a864886f70d020505000410";
//_RSASIGN_DIHEAD['sha384'] = "3041300d060960864801650304020205000430";
//_RSASIGN_DIHEAD['sha512'] = "3051300d060960864801650304020305000440";
var _RSASIGN_HASHHEXFUNC = [];
_RSASIGN_HASHHEXFUNC['sha1'] = sha1.hex;
_RSASIGN_HASHHEXFUNC['sha256'] = sha256.hex;

// ========================================================================
// Signature Generation
// ========================================================================

function _rsasign_getHexPaddedDigestInfoForString(s, keySize, hashAlg)
{
    var pmStrLen = keySize / 4;
    var hashFunc = _RSASIGN_HASHHEXFUNC[hashAlg];
    var sHashHex = hashFunc(s);

    var sHead = "0001";
    var sTail = "00" + _RSASIGN_DIHEAD[hashAlg] + sHashHex;
    var sMid = "";
    var fLen = pmStrLen - sHead.length - sTail.length;
    for (var i = 0; i < fLen; i += 2)
    {
        sMid += "ff";
    }
    sPaddedMessageHex = sHead + sMid + sTail;
    return sPaddedMessageHex;
}

function _rsasign_signString(s, hashAlg)
{
    var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), hashAlg);
    var biPaddedMessage = parseBigInt(hPM, 16);
    var biSign = this.doPrivate(biPaddedMessage);
    var hexSign = biSign.toString(16);
    return hexSign;
}

function _rsasign_signStringWithSHA1(s)
{
    var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), 'sha1');
    var biPaddedMessage = parseBigInt(hPM, 16);
    var biSign = this.doPrivate(biPaddedMessage);
    var hexSign = biSign.toString(16);
    return hexSign;
}

function _rsasign_signStringWithSHA256(s)
{
    var hPM = _rsasign_getHexPaddedDigestInfoForString(s, this.n.bitLength(), 'sha256');
    var biPaddedMessage = parseBigInt(hPM, 16);
    var biSign = this.doPrivate(biPaddedMessage);
    var hexSign = biSign.toString(16);
    return hexSign;
}

// ========================================================================
// Signature Verification
// ========================================================================

function _rsasign_getDecryptSignatureBI(biSig, hN, hE)
{
    var rsa = new RSAKey();
    rsa.setPublic(hN, hE);
    var biDecryptedSig = rsa.doPublic(biSig);
    return biDecryptedSig;
}

function _rsasign_getHexDigestInfoFromSig(biSig, hN, hE)
{
    var biDecryptedSig = _rsasign_getDecryptSignatureBI(biSig, hN, hE);
    var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
    return hDigestInfo;
}

function _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo)
{
    for (var algName in _RSASIGN_DIHEAD)
    {
        var head = _RSASIGN_DIHEAD[algName];
        var len = head.length;
        if (hDigestInfo.substring(0, len) == head)
        {
            var a = [algName, hDigestInfo.substring(len)];
            return a;
        }
    }
    return [];
}

function _rsasign_verifySignatureWithArgs(sMsg, biSig, hN, hE)
{
    var hDigestInfo = _rsasign_getHexDigestInfoFromSig(biSig, hN, hE);
    var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);
    if (digestInfoAry.length == 0) return false;
    var algName = digestInfoAry[0];
    var diHashValue = digestInfoAry[1];
    var ff = _RSASIGN_HASHHEXFUNC[algName];
    var msgHashValue = ff(sMsg);
    return (diHashValue == msgHashValue);
}

function _rsasign_verifyHexSignatureForMessage(hSig, sMsg)
{
    var biSig = parseBigInt(hSig, 16);
    var result = _rsasign_verifySignatureWithArgs(sMsg, biSig, this.n.toString(16), this.e.toString(16));
    return result;
}

function _rsasign_verifyString(sMsg, hSig)
{
    hSig = hSig.replace(/[ \n]+/g, "");
    var biSig = parseBigInt(hSig, 16);
    var biDecryptedSig = this.doPublic(biSig);
    var hDigestInfo = biDecryptedSig.toString(16).replace(/^1f+00/, '');
    var digestInfoAry = _rsasign_getAlgNameAndHashFromHexDisgestInfo(hDigestInfo);

    if (digestInfoAry.length == 0) return false;
    var algName = digestInfoAry[0];
    var diHashValue = digestInfoAry[1];
    var ff = _RSASIGN_HASHHEXFUNC[algName];
    var msgHashValue = ff(sMsg);
    return (diHashValue == msgHashValue);
}

RSAKey.prototype.signString = _rsasign_signString;
RSAKey.prototype.signStringWithSHA1 = _rsasign_signStringWithSHA1;
RSAKey.prototype.signStringWithSHA256 = _rsasign_signStringWithSHA256;

RSAKey.prototype.verifyString = _rsasign_verifyString;
RSAKey.prototype.verifyHexSignatureForMessage = _rsasign_verifyHexSignatureForMessage;



























