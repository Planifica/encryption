[![Code Climate](https://codeclimate.com/github/Planifica/encryption/badges/gpa.svg)](https://codeclimate.com/github/Planifica/encryption)
# CollectionEncryption
## What is it?
Client-Side Encryption for Mongo Collections in a Meteor app.
This package supports:
* Automatically generating a ECC keypair for every user
* Declaring which fields of which collection you should be encrypted
* Sharing encrypted information with other users

This package helps you write Meteor applications that support encryption with ease.
Also see this [blog post](https://medium.com/@PhilippSpo/client-side-encryption-in-meteor-3ae982e557a8) to get started.

## Getting Started
First install the package:
```
meteor add planifica:encryption
```
### Generating keypairs for every user
Then you need to trigger the ECC keypair generation. Optimally you do this when the user first signes in. Note that you need the (unencrypted) password of the user here in order for the package to encrypt the private key of the user (with the user's password). This makes sure that the private key can be stored securely in the database, without the user having the need to remember it. The private key will automatically be stored inside the users profile (in encrypted form) and the public key in the users principal object.  
Also once a user logs in, the users private key needs to be decrypted and made available for en-/decrypting data. Again you need the raw password of the user in order to decrypt the private key.
This is how you trigger both - the key generation (on first sign in) and the private key decryption (on every sign in):
```js
EncryptionUtils.onSignIn(password);
```
We recommend using [Useraccounts](https://atmospherejs.com/useraccounts/core) in your apps, which has a `onSubmitHook`, which you can use for this:

```js
AccountsTemplates.configure({
    onSubmitHook: function (error, state) {
        if (error) {
            return;
        }
        var password = $('#at-pwd-form :input#at-field-password').val();
        if (state === 'signIn' || state === 'signUp') {
			EncryptionUtils.onSignIn(password);
		}
    }
});
```
    
### Subscribing to the Principals collection
The package internally uses the Principals collection, which stores all kinds of encryption information for specific documents, like private and public keys, nonces and information about shared documents.  
So always make sure that you subscribe to the principals collection, if you want to access your encrypted data:
```js
Meteor.subscribe('principals');
```
This subscribes to all the principals that the current user is the owner of and to all principals that are shared with the current user.  
You can also subscribe to the principal of a specific document by passing the id of the document as the first param:
```js
Meteor.subscribe('principals', _id);
```
### Encrypting a collection
    
In order to encrypt a collection you need to create a instance of `CollectionEncryption` and do some configuration:
```js
if (Meteor.isClient) {
    // define fields to be encrypted
    var fields = ['message'];
    // init encryption on collection Messages
    DataObjectsEncryption = new CollectionEncryption(
        Messages,
        fields,
        {}
    );
}
```
The CollectionEncryption constructor takes the following parameters:
* The collection you want to encrypt
* An array of fields that you want to encrypt (no sub-properties supported at the moment)
* Configuration object
    * `onKeyGenerated` - callback function that gets called once a key is generated
    * `onFinishedDocEncryption` - callback function that gets called once a document is inserted and encrypted

### Sharing a document
In order to share a document of a specific collection you need to call the `shareDocWithUser` function on your CollectionEncryption instance:
```js
MessagesEncryption.shareDocWithUser(docId, userToShareWithId);
```
If you want to share a document in the moment that it is added to the collection (e.g. in a chat) you can call this function in the `onFinishedDocEncryption` callback:
```js
// init encryption on collection Messages
MessagesEncryption = new CollectionEncryption(WelcomeTexts, fields, {

    onFinishedDocEncryption: function (doc) {
        // share the inserted doc with the chat partner
        MessagesEncryption.shareDocWithUser(
            doc._id,
            doc.partnerId
        );
    }
});
 ```
### Configuration
At the moment there is not much to configure, but we will extend this section in the future.
You can call the `configure` method on the EncryptionUtils object to do some more configuration:
```js
EncryptionUtils.configure(config);
```
Options:
* `enforceEmailVerification`: `Boolean`

## How secure is it?
Like every other system, what it comes down to is the password of the user. If the user's password is not secure, his data also is not.
For every encryption we use the [TweetNaCl.js](https://github.com/dchest/tweetnacl-js), which is a port of [TweetNaCl](http://tweetnacl.cr.yp.to/) / [NaCl](http://nacl.cr.yp.to/) to JavaScript for modern browsers. At the moment this package does *not* authenticate the partners that are communicating with each other (e.g. with Diffie-Hellman)!
## What is the goal of this package?
The goal of this package is to create a scenario, where you (as a developer/product owner) can be sure that you have no access to the users data, which you can also assure to your users.  
Also there is no way of hacking only one key (e.g. your server's or database's password), which grants access to all the data in the system.

## Side notes
This package started with using RSA and AES for encryption as proposed in this [paper](http://css.csail.mit.edu/mylar/). However we switched to using the NaCl library, which uses the far more efficient alorithms ECC and Salsa20.

### Browser Support
The browser support comes down to the support of UInt8Arrays, which are [not supported](http://caniuse.com/#feat=typedarrays) in IE9 and IE8.

## Licence
MIT. (c) maintained by Planifica.
