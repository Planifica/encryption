[![Code Climate](https://codeclimate.com/github/Planifica/encryption/badges/gpa.svg)](https://codeclimate.com/github/Planifica/encryption)
# CollectionEncryption
## What is it?
Client-Side Encryption for Mongo Collections in a Meteor app.
This package supports:
* Automatically generating a ECC keypair for every user
* Declaring which fields of which collection you should be encrypted
* Sharing encrypted information with other users

This package helps you write Meteor applications that support encryption with ease.
Also see this [blog post]() to get started.

## Getting Started
First install the package:
```
meteor add planifica:encryption
```
### Generating keypairs for every user
Then you need to trigger the ECC keypair generation. Optimally you do this once a user has created his account. Note that you need the (unencrypted) password of the user here in order for the package to encrypt the private key of the user (with the user's password). This makes sure that the private key can be stored securely in the database, without the user having the need to remember it. This is how you trigger the keypair generation. The private key will automatically be stored inside the users profile (in encrypted form) and the public key in the users principal object.

    EncryptionUtils.extendProfile(password, function () {
      // callback once keypair is generated finished
    });
    
Additionaly once a user logs in, you need to tell the package to decrypt the users private key and make it available for en-/decrypting data. Again you need the raw password of the user in order to decrypt the private key.

    EncryptionUtils.onSignIn(password);
    
We recommend using [Useraccounts](https://atmospherejs.com/useraccounts/core) in your apps, which has a `onSubmitHook`, which you can use for triggering the generation of the keypair and the decryption of the users private key:

    AccountsTemplates.configure({
        onSubmitHook: function (error, state) {
            if (error) {
                return;
            }
            var password = $('#at-pwd-form :input#at-field-password').val();
            if (state === 'signIn') {
                EncryptionUtils.onSignIn(password);
            } else if (state === "signUp") {
                EncryptionUtils.extendProfile(password, function () {
                    // Users Keypair successfully generated
                });
                // done
            }
        }
    });
    
### Subscribing to the Principals collection
The package internally uses the Principals collection, which stores all kinds of encryption information for specific documents, like private and public keys, nonces and information about shared documents.  
So always make sure that you subscribe to the principals collection, if you want to access your encrypted data:

    Meteor.subscribe('principals');
    
This subscribes to all the principals that the current user is the owner of and to all principals that are shared with the current user.  
You can also subscribe to the principal of a specific document by passing the id of the document as the first param:

    Meteor.subscribe('principals, _id);

### Encrypting a collection
    
In order to encrypt a collection you need to create a instance of `CollectionEncryption` and do some configuration:

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
    
The CollectionEncryption constructor takes the following parameters:
* The collection you want to encrypt
* An array of fields that you want to encrypt (no sub-properties supported at the moment)
* Configuration object
    * `onKeyGenerated` - callback function that gets called once a key is generated
    * `onFinishedDocEncryption` - callback function that gets called once a document is inserted and encrypted

## How secure is it?
Like every other system, what it comes down to is the password of the user. If the user's password is not secure, his data also is not.
For every encryption we use the [TweetNaCl.js](https://github.com/dchest/tweetnacl-js), which is a port of [TweetNaCl](http://tweetnacl.cr.yp.to/) / [NaCl](http://nacl.cr.yp.to/) to JavaScript for modern browsers. At the moment this package does *not* authenticate the partners that are communicating with each other (e.g. with Diffie-Hellman)!
## What is the goal of this package?
The goal of this package is to create a scenario, where you (as a developer/product owner) can be sure that you have no access to the users data, which you can also assure to your users.  
Also there is no way of hacking only one key (e.g. your server's or database's password), which grants access to all the data in the system.

## Side notes
This package started with using RSA and AES for encryption as proposed in this [paper](http://css.csail.mit.edu/mylar/). However we switched to using the NaCl library, which uses the far more efficient alorithms ECC and Salsa20.

## Licence
MIT. (c) maintained by Planifica.
