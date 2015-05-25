
Generating RSA keys is a characteristically CPU intensive operation. This presents problems when operating on weak devices (such as the iPhone 3G) in environments under strict computation restrictions (such as safari mobile's 10 second javascript execution timeout).

What is needed is an RSA key generation library that operates asynchronously in order to chug through the 2+ minutes of computation time required to generate a 512 RSA key on a weak device without bumping against the computation restrictions enforced by the safari mobile execution environment.

Some nearly suitable libraries do exist, but all of them fall short in some fashion.

* Probably the closest is this **asynchronous keygen** from Atsushi Oka
  http://ats.oka.nu/titaniumcore/js/crypto/readme.txt
  However, the interface for Ats Oka's library is not simple and the architecture of the code leaves something to be desired.

* **Cryptico** is another library featuring RSA key generation which is also touted as a sort of all-in-one solution 
  http://code.google.com/p/cryptico/
  However, this library really just glues together a bunch of already-available libraries and packages them as a unit.

* **jsbn** is the underlying RSA key generator packaged with Cryptico and is available on its own
  http://www-cs-students.stanford.edu/~tjw/jsbn/
  This library has a fairly simple interface and is relatively fast and compact meeting most of my requirements.
  However, *this library doesn't do asynchronous key generation*.  

But *we can fix that*.

jsbn RSA keygen times out after 11 seconds on the iPhone 3G for even a 256 bit key but with a little fenangling and a lot of setTimeouts, we can get it to handle a key of virtually any size for which the user has the patience to wait.

Here's an example of the new async interface:

```javascript
key = new RSAKey();
key.generateAsync(512, "03", function(){
    var pubKey = hex2b64(key.n.toString(16));
    alert(pubKey);
});
```

This was a great exercise in how to turn synchronous javascript into asynchronous javascript. Taking procedural code and breaking those for loops into recursive functions was a mind bender but once I figured out how it generally ought to work, each function became easier to port. 

Originally I did it all inline, but later I ripped it all out into a separate file which extends Tom Wu's jsbn.