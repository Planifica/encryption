// Depends on jsbn.js and rng.js

// Version 1.1: support utf-8 encoding in pkcs1pad2

// convert a (hex) string to a bignum object
function parseBigInt(str,r) {
  return new BigInteger(str,r);
}

function linebrk(s,n) {
  var ret = "";
  var i = 0;
  while(i + n < s.length) {
    ret += s.substring(i,i+n) + "\n";
    i += n;
  }
  return ret + s.substring(i,s.length);
}

function byte2Hex(b) {
  if(b < 0x10)
    return "0" + b.toString(16);
  else
    return b.toString(16);
}

// PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
function pkcs1pad2(s,n) {
  if(n < s.length + 11) { // TODO: fix for utf-8
    throw new Error("Message too long for RSA");
  }
  var ba = new Array();
  var i = s.length - 1;
  while(i >= 0 && n > 0) {
    var c = s.charCodeAt(i--);
    if(c < 128) { // encode using utf-8
      ba[--n] = c;
    }
    else if((c > 127) && (c < 2048)) {
      ba[--n] = (c & 63) | 128;
      ba[--n] = (c >> 6) | 192;
    }
    else {
      ba[--n] = (c & 63) | 128;
      ba[--n] = ((c >> 6) & 63) | 128;
      ba[--n] = (c >> 12) | 224;
    }
  }
  ba[--n] = 0;
  var rng = new SecureRandom();
  var x = new Array();
  while(n > 2) { // random non-zero pad
    x[0] = 0;
    while(x[0] == 0) rng.nextBytes(x);
    ba[--n] = x[0];
  }
  ba[--n] = 2;
  ba[--n] = 0;
  return new BigInteger(ba);
}

// "empty" RSA key constructor
RSAKey = function () {
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
function RSASetPublic(N,E) {
  if(N != null && E != null && N.length > 0 && E.length > 0) {
    this.n = parseBigInt(N,16);
    this.e = parseInt(E,16);
  }
  else
    throw new Error("Invalid RSA public key");
}

// Perform raw public operation on "x": return x^e (mod n)
function RSADoPublic(x) {
  return x.modPowInt(this.e, this.n);
}

// Return the PKCS#1 RSA encryption of "text" as an even-length hex string
function RSAEncrypt(text) {
  var m = pkcs1pad2(text,(this.n.bitLength()+7)>>3);
  if(m == null) return null;
  var c = this.doPublic(m);
  if(c == null) return null;
  var h = c.toString(16);
  if((h.length & 1) == 0) return h; else return "0" + h;
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

//From git://github.com/titanous/pem-js.gitmaster

var ASNIntValue, ASNLength, int2hex;
function privatePEM() {
  var encoded;
  encoded = '020100';
  encoded += ASNIntValue(this.n, true);
  encoded += ASNIntValue(this.e, false);
  encoded += ASNIntValue(this.d, false);
  encoded += ASNIntValue(this.p, true);
  encoded += ASNIntValue(this.q, true);
  encoded += ASNIntValue(this.dmp1, true);
  encoded += ASNIntValue(this.dmq1, false);
  encoded += ASNIntValue(this.coeff, false);
  encoded = '30' + ASNLength(encoded) + encoded;
  return "-----BEGIN RSA PRIVATE KEY-----\n" + encode64(chars_from_hex(encoded)) + "\n-----END RSA PRIVATE KEY-----";
};
RSAKey.prototype.privatePEM = privatePEM;

function publicPEM() {
  var encoded;
  encoded = ASNIntValue(this.n, true);
  encoded += ASNIntValue(this.e, false);
  encoded = '30' + ASNLength(encoded) + encoded;
  encoded = '03' + ASNLength(encoded, 1) + '00' + encoded;
  encoded = '300d06092a864886f70d0101010500' + encoded;
  encoded = '30' + ASNLength(encoded) + encoded;
  return "-----BEGIN PUBLIC KEY-----\n" + encode64(chars_from_hex(encoded)) + "\n-----END PUBLIC KEY-----";
};
RSAKey.prototype.publicPEM = publicPEM;

RSAKey.prototype.parsePEM = function(pem) {
  pem = ASN1.decode(Base64.unarmor(pem)).sub;
  return this.setPrivateEx(pem[1].content(), pem[2].content(), pem[3].content(), pem[4].content(), pem[5].content(), pem[6].content(), pem[7].content(), pem[8].content());
};

ASNIntValue = function(integer, nullPrefixed) {
  integer = int2hex(integer);
  if (nullPrefixed) {
    integer = '00' + integer;
  }
  return '02' + ASNLength(integer) + integer;
};

ASNLength = function(content, extra) {
  var length;
  if (!(typeof extra !== "undefined" && extra !== null)) {
    extra = 0;
  }
  length = (content.length / 2) + extra;
  if (length > 127) {
    length = int2hex(length);
    return int2hex(0x80 + length.length / 2) + length;
  } else {
    return int2hex(length);
  }
};

int2hex = function(integer) {
  integer = integer.toString(16);
  if (integer.length % 2 !== 0) {
    integer = '0' + integer;
  }
  return integer;
};

/* CryptoMX Tools - Base64 encoder/decoder
 * http://www.java2s.com/Code/JavaScriptDemo/Base64EncodingDecoding.htm
 *
 * Copyright (C) 2004 - 2006 Derek Buitenhuis
 * Modified February 2009 by TimStamp.co.uk
 * GPL v2 Licensed
 */
function encode64(a){a=a.replace(/\0*$/g,"");var b="",d,e,g="",h,i,f="",c=0;do{d=a.charCodeAt(c++);e=a.charCodeAt(c++);g=a.charCodeAt(c++);h=d>>2;d=(d&3)<<4|e>>4;i=(e&15)<<2|g>>6;f=g&63;if(isNaN(e))i=f=64;else if(isNaN(g))f=64;b=b+"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".charAt(h)+"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".charAt(d)+"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".charAt(i)+"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".charAt(f)}while(c<
a.length);a="";b=b.split("");for(c=0;c<b.length;c++){if(c%64==0&&c>0)a+="\n";a+=b[c]}b.join();b=a%4;for(c=0;c<b;c++)a+="=";return a}
function decode64(a){var b="",d,e,g="",h,i="",f=0;a=a.replace(/[^A-Za-z0-9\+\/\=\/n]/g,"");do{d="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".indexOf(a.charAt(f++));e="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".indexOf(a.charAt(f++));h="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".indexOf(a.charAt(f++));i="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=".indexOf(a.charAt(f++));d=d<<2|e>>4;e=(e&15)<<4|h>>2;g=(h&3)<<
6|i;b+=String.fromCharCode(d);if(h!=64)b+=String.fromCharCode(e);if(i!=64)b+=String.fromCharCode(g)}while(f<a.length);return b=b.replace(/\0*$/g,"")};

/* JavaScript ASCII Converter
 * http://www.vortex.prodigynet.co.uk/misc/ascii_conv.html
 *
 * TPO 2001/2004
 * Modified Feb 2009 by Tim Stamp (timstamp.co.uk)
 * License Unknown
 */
function chars_from_hex(a){var c="";a=a.replace(/^(0x)?/g,"");a=a.replace(/[^A-Fa-f0-9]/g,"");a=a.split("");for(var b=0;b<a.length;b+=2)c+=String.fromCharCode(parseInt(a[b]+""+a[b+1],16));return c};
//RSAKey.prototype.encrypt_b64 = RSAEncryptB64;
