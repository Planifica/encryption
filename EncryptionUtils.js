/* global EncryptionUtils:true */

var CONFIG_PAT = {
    enforceEmailVerification: Match.Optional(Boolean)
};

// private key
// will be flushed once the user signs out
var signedInSession = new PersistentReactiveDict('mySession');
// method that retunrsn an Uint8Array of the private key
var getPrivateKey = function () {
  var privateKeyObj = signedInSession.get('privateKey');
  if (privateKeyObj && privateKeyObj.privateKey) {
    return new Uint8Array(_.values(privateKeyObj.privateKey));
  }
  return null;
};

EncryptionUtils = {
    /**
     * standard options
     */
    options: {
        enforceEmailVerification: true
    },

    hasPrivateKey: function () {
      return !_.isNull(getPrivateKey());
    },
    /**
     * sets the options for all encryptions functions
     * @param options
     */
    configure: function (options) {
        check(options, CONFIG_PAT);

        this.options = _.defaults(options, this.options);
    },
    /**
     * encrypts certain fields of the given document
     * @param doc - the document to encrypt
     * @param fields - the fields of the document to be dercypted
     * @param name - the name of the principal that belongs to the document
     */
    encryptDocWithId: function (doc, fields, name, documentKey) {
        var self = this,
            // client only so this works :)
            user = Meteor.user(),
            newDoc = {},
            symNonce = self.generate24ByteNonce();

        // fetch a potential existing principal
        // - this might be the case in an update
        var existingPrincipal = Principals.findOne({
            dataType: name,
            dataId: doc._id
        });

        if (existingPrincipal) {
            // if there is a principal get the "old" document key and use it
            documentKey = self.getDocumentKeyOfPrincipal(existingPrincipal);
            symNonce = existingPrincipal.symNonce;
        }
        // encrypt the desired fields
        _.each(fields, function (field) {
            if(doc.hasOwnProperty(field)){
              newDoc[field] = self.symEncryptWithKey(doc[field],
                  symNonce, documentKey);
            }
        });
        if (existingPrincipal) {
            // if the doc was just updated then return
            // since it already has a valid principal
            // and is potentially shared with users
            return newDoc;
        }

        //generate new 24Byte asymNonce
        var asymNonce = self.generate24ByteNonce();
        var keyPairForDocumentKey = nacl.box.keyPair();

        // get the principal of the user
        var userPrincipal = self.getPrincipal('user', user._id);
        if (!userPrincipal) {
            console.warn('no user principal found');
            return;
        }
        // encrypt the document key with the users public key -- needs to be RSA
        var encryptedDocumentKey = self.asymEncryptWithKey(documentKey,
            asymNonce,
            userPrincipal.publicKey, keyPairForDocumentKey.secretKey
        );

        // create the principle in the database
        Principals.insert({
            dataType: name,
            dataId: doc._id,
            encryptedPrivateKeys: [{
                userId: user._id,
                key: encryptedDocumentKey,
                asymNonce: asymNonce
            }],
            publicKey: keyPairForDocumentKey.publicKey,
            privateKey: keyPairForDocumentKey.secretKey,
            symNonce: symNonce
        });

        return newDoc;
    },
    /**
     * decrypts certain fields of the given document
     * @param doc - the document to decrypt
     * @param fields - the fields of the document to be dercypted
     * @param name - the name of the principal that belongs to the document
     */
    decryptDoc: function (doc, fields, name) {
        var self = this;
        // get the principal of the document
        var principal = self.getPrincipal(name, doc._id);
        // return if the doc was not encrypted correctly
        if (!principal) {
            console.warn('no document principal found for type ' + name +
                ' and docId ' + doc._id);
            return doc;
        }
        // get decrypted private key of principal -- needs to be async
        var decryptedDocumentKey = self.getDocumentKeyOfPrincipal(
            principal);
        // return if something went wrong
        if (!decryptedDocumentKey) {
            return doc;
        }
        // decrypt each given field
        _.each(fields, function (field) {
            if (doc.hasOwnProperty(field)) {
                doc[field] = self.symDecryptWithKey(doc[field],
                    principal.symNonce,
                    decryptedDocumentKey);
            }
        });
        // set encrypted to false for better ui state handling
        doc.encrypted = false;

        return doc;
    },
    /**
     * encrypts the given message asymmetrically with the given (public) key
     * @param message - the message to be encrypted
     * @param nonce - the nonce used for the encryption
     * @param publicKey - the public key that is used to encrypt the message
     * @param secretKey - the private key that represents the message
     */
    asymEncryptWithKey: function (message, nonce, publicKey, secretKey) {
        return nacl.box(message, nonce, publicKey, secretKey);
    },
    /**
     * encrypts the given message symmetrically with the given  key
     * @param message - the message to be encrypted
     * @param nonce - the nonce used for the encryption
     * @param key - key that is used to en-/decrypt the message
     */
    symEncryptWithKey: function (message, nonce, key) {
        var returnAsString = _.isString(message);
        if (returnAsString) {
            message = nacl.util.decodeUTF8(message);
        }
        var encryptedMessage = nacl.secretbox(message, nonce, key);
        if (returnAsString) {
            return nacl.util.encodeBase64(encryptedMessage);
        }
        return encryptedMessage;
    },
    /**
     * encrypts the given message symmetrically with the users' private key
     * @param message - the message to be encrypted
     * @param nonce - the nonce used for the encryption
     */
    symEncryptWithCurrentUsersPrivateKey: function (message, nonce) {
        var self = this;
        return self.symEncryptWithKey(message, nonce, getPrivateKey());
    },
    /**
     * decrypts the given message symmetrically with the users' private key
     * @param message - the message to be decrypted
     * @param nonce - the nonce used for the decryption
     */
    symDecryptWithCurrentUsersPrivateKey: function (message, nonce) {
        var self = this;
        return self.symDecryptWithKey(message, nonce, getPrivateKey());
    },
    /**
     * decrypts the given message asymmetrically with the given (private) key
     * @param message - the message to be decrypted
     * @param nonce - the nonce used for the decryption
     * @param publicKey - the public key that represents the message
     * @param secretKey - the private key of the user that wants to decrypt the message
     */
    asymDecryptWithKey: function (message, nonce, publicKey, secretKey) {
        return nacl.box.open(message, nonce, publicKey, secretKey);
    },
    /**
     * decrypts the given message symmetrically with the given  key
     * @param message - the message to be decrypted
     * @param nonce - the nonce used for the decryption
     * @param key - key that is used to en-/decrypt the message
     */
    symDecryptWithKey: function (cipher, nonce, key) {
        var returnAsString = _.isString(cipher);
        if (returnAsString) {
            cipher = nacl.util.decodeBase64(cipher);
        }
        var decryptedMessage = nacl.secretbox.open(cipher, nonce, key);
        if (returnAsString) {
            return nacl.util.encodeUTF8(decryptedMessage);
        }
        return decryptedMessage;
    },
    /**
     * generates a random key which may be used for symmetric crypto
     */
    generateRandomKey: function () {

        if (window.secureShared && window.secureShared.generatePassphrase) {
            return nacl.util.decodeUTF8(CryptoJS.lib.WordArray.random(16).toString());
        }
        // TODO no else yet
    },
    /**
     * get private key of given principal
     * @param principal
     */
    getDocumentKeyOfPrincipal: function (principal) {

        // check if the principal object without the _id matches the schema
        check(_.omit(principal, '_id'), Principals.simpleSchema());
        if (!principal) {
            return;
        }

        var self = this,
            user = Meteor.user(),
            searchObj = {
                userId: user._id
            },
            privateKey = getPrivateKey(),
            encryptedKeys = _.where(principal.encryptedPrivateKeys,
                searchObj);

        if (!encryptedKeys.length) {
            return;
        }
        var publicKeyForDocumentKey = principal.publicKey;
        // return decrypted key
        return self.asymDecryptWithKey(encryptedKeys[0].key,
            encryptedKeys[0].asymNonce, publicKeyForDocumentKey,
            privateKey);
    },
    /**
     * search if a principal for the given params exists
     * @param type - the type of the principal that is searched for
     * @param dataId - the id of the data object that is managed by the pricipal
     */
    getPrincipal: function (type, dataId) {
        return Principals.findOne({
            dataType: type,
            dataId: dataId
        });
    },
    /**
     * shares the given doc with the given user
     * by encrypting the principal key of the doc with the publicKey of the user
     * @param docId
     * @param docType - the type of the principal that is used for the doc
     * @param userId - this might NOT be the currently signed in user
     */
    shareDocWithUser: function (docId, docType, userId) {
        var self = this,
            asymNonce = self.generate24ByteNonce();

        // find principal of user to share post with
        var userPrincipal = self.getPrincipal('user', userId);
        if (!userPrincipal) {
            console.warn('no principal found for user with id: ' +
                userId);
            return;
        }

        // fint principal of post
        var documentPrincipal = self.getPrincipal(docType, docId);
        if (!documentPrincipal) {
            console.warn('no documentPrincipal found for ' + docType +
                ' with id: ' +
                docId);
            return;
        }

        var userPublicKey = userPrincipal.publicKey;
        var secretKeyForDocumentKey = documentPrincipal.privateKey;
        // get the decrypted key that was used to encrypt the document
        var documentKey = self.getDocumentKeyOfPrincipal(
            documentPrincipal);
        // encrypted the document key with the public key of the user that
        // the document should be shared with
        var encryptedDocumentKey = self.asymEncryptWithKey(documentKey,
            asymNonce, userPublicKey, secretKeyForDocumentKey);

        // update the principal
        Principals.update({
            _id: documentPrincipal._id
        }, {
            $push: {
                encryptedPrivateKeys: {
                    userId: userId,
                    key: encryptedDocumentKey,
                    asymNonce: asymNonce
                }
            }
        });
    },
    /**
     * unshares the given doc with the given user
     * by removing the given user's id and corresponding (encrypted) document-key from the documents principal
     * @param docId
     * @param docType - the type of the principal that is used for the doc
     * @param userId - this might NOT be the currently signed in user
     */
    unshareDocWithUser: function (docId, docType, userId) {
        var self = this;

        // fint principal of post
        var principal = self.getPrincipal(docType, docId);
        if (!principal) {
            console.warn('no principal found for ' + docType +
                ' with id: ' +
                docId);
            return;
        }

        // update the principal
        Principals.update({
            _id: principal._id
        }, {
            $pull: {
                encryptedPrivateKeys: {
                    userId: userId
                }
            }
        });
    },
    /**
     * checks if the given document is shared with the given user via the principal
     * @param docId
     * @param docType - the type of the principal that is used for the doc
     * @param userId - this might NOT be the currently signed in user
     */
    checkIfDocIsSharedWithUser: function (docId, docType, userId) {
        // find principle
        var principal = Principals.findOne({
            dataType: docType,
            dataId: docId,
            'encryptedPrivateKeys.userId': userId
        });
        // check if there is a principle
        if (!principal) {
            console.warn('no principal found for ' + docType +
                ' with id: ' +
                docId);
            return;
        }
        return principal;

    },
    /**
     * extends the current user's profile with his (encrypted) privateKey
     * this key gets encrypted with his password symmetrically
     * @param password - plaintext password of the user
     * @param callback - completion hander
     */
    extendProfile: function (password) {
        var self = this;
        var userId = Meteor.userId();
        // generate keypair
        var keyPair = nacl.box.keyPair();

        // encrypt the user's private key
        var nonce = self.generate24ByteNonce();
        password = self.generate32ByteKeyFromPassword(password);

        var privateKey = self.symEncryptWithKey(
            keyPair.secretKey,
            nonce,
            password.byteArray
        );

        // store the raw private key in the session as base64 string
        signedInSession.setAuth('privateKey', {privateKey: keyPair.secretKey});

        // use meteor call since the client might/should not be allowd
        // to update the user document client-side
        // store the private key as uInt8Array
        Meteor.call('storeEncryptedPrivateKey', privateKey);

        // add a principal for the user
        Principals.insert({
            dataType: 'user',
            dataId: userId,
            addedPasswordBytes: password.randomBytes,
            // store the public key as uInt8Array
            publicKey: keyPair.publicKey,
            // store the nonce key as uInt8Array
            symNonce: nonce
        });
    },
    /**
     * decrypts the users privateKey with the given password symmetrically
     * @param password
     */
    onSignIn: function (password) {
        var self = this,
            user = Meteor.user();

        if (self.options.enforceEmailVerification === true && user.emails[
                0].verified !== true) {
            console.warn(
                'The users email is not verified and since ' +
                'enforceEmailVerification is enabled the encryption will not continue'
            );
            return;
        }
        // check if user already has a keypair
        if (user.profile && user.profile.privateKey) {
            console.info('private key found -> decrypting it now');
            Meteor.subscribe('principals', function () {
                var principal = self.getPrincipal('user', user._id);

                if (!principal) {
                    console.warn('no user principal found');
                    return;
                }

                password = self.generate32ByteKeyFromPassword(
                    password, principal.addedPasswordBytes);
                // decrypt private key of the user using his password and nonce
                var privateKey = self.symDecryptWithKey(
                    user.profile.privateKey,
                    principal.symNonce,
                    password.byteArray
                );

                signedInSession.setAuth('privateKey', {privateKey: privateKey});
            });
        } else {
            console.info('no private key found -> generating one now');
            // if not it is probably his first login -> generate keypair
            self.extendProfile(password);
        }
    },

    /**
     * generate 24Byte nonce
     */
    generate24ByteNonce: function () {
        return nacl.randomBytes(24);
    },

    /**
     * generate 32Byte Key from password
     * @param String
     */
    generate32ByteKeyFromPassword: function (password, randomBytes) {
        var self = this,
            byteArray = nacl.util.decodeUTF8(password);

        if (byteArray.length < 32) {
            // if there are no randomBytes provided -> generate some
            if (!randomBytes) {
                randomBytes = nacl.randomBytes(32 - byteArray.length);
            }
            // store the random bytes so we can use them again when we want to decrypt
            byteArray = self.appendBuffer(byteArray, randomBytes);

        } else {
            byteArray = byteArray.slice(0, 31);
        }
        // return the byte array and the added bytes
        return {
            byteArray: byteArray,
            randomBytes: randomBytes
        };
    },

    /**
     * Creates a new Uint8Array based on two different uInt8Arrays
     *
     * @private
     * @param {uInt8Array} buffer1 The first buffer.
     * @param {uInt8Array} buffer2 The second buffer.
     * @return {uInt8Array} The new ArrayBuffer created out of the two.
     */
    appendBuffer: function (buffer1, buffer2) {
        var tmp = new Uint8Array(buffer1.length + buffer2.length);
        tmp.set(new Uint8Array(buffer1), 0);
        tmp.set(new Uint8Array(buffer2), buffer1.length);
        return tmp;
    }
};
