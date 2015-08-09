[![Code Climate](https://codeclimate.com/github/Planifica/encryption/badges/gpa.svg)](https://codeclimate.com/github/Planifica/encryption)
# CollectionEncryption
## What is it?
Client-Side Encryption for Mongo Collections in a Meteor App.
This package supports:
* Automatically generating a RSA keypair for every user
* Declaring which fields of which collection you want to have encrypted
* Sharing encrypted information with other users

## Getting Started
First install the package:
```
meteor add planifica:encryption
```
Then you need to generate RSA Keypairs for every user. Optimally you do this once a user has created his account. Note that you need the unencrypted password of the user here in order for the package to encrypt the private key of the user (with the user's password). This makes sure that the private key can be stored securely in the database.

    EncryptionUtils.extendProfile(password, function () {
      // callback once keypair is generated finished
    });
    
Additionaly once a user logs in, you need to tell the package to decrypt the users private key and make it available for en-/decrypting data. Again you need the raw password of the user in order to encrypt the private key.

    EncryptionUtils.onSignIn(password);
    
We use [Useraccounts](https://atmospherejs.com/useraccounts/core) in all of our apps, which has a `onSubmitHook`, which we can use for generating and decrypting the users private key:

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
    
Then you need to create a Instance of `CollectionEncryption` and do some configuration:

    if (Meteor.isClient) {
        // define fields to be encrypted
        var fields = ['message'];
        // init encryption on collection Messages
        DataObjectsEncryption = new CollectionEncryption(Messages, 'message', fields, Schema.Messages, false);
    }
    
The CollectionEncryption constructor takes the following parameters:
* Collection
* Name to identify a encrypted object
* Array of fields that you want to encrypt
* Schema for your collection ([SimpleSchema](https://github.com/aldeed/meteor-simple-schema))
* Boolean that indicates wether to use Async encryption for encrypting messages or not (async is slow!)

## How secure is it?
Like every other System, what it comes down to is the password of the user. If the user's password is not secure, his data also is not.
For every asynchronous encryption we use [RSA](http://www-cs-students.stanford.edu/~tjw/jsbn/) with 2048 bit keys (creating the private and public keys of the user) and for all synchronous keys we use [AES-256](https://code.google.com/p/crypto-js/#AES) (encrypting the actual data).
## What is the goal of this package?
The goal of this package is to create a scenario, where you (as a developer/product owner) can be sure that you have no access to the users data, which you can also assure to your users.  
Also there is no way of hacking one key (e.g. your server's or database's password) to all the data in the system.
