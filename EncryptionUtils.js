/* global EncryptionUtils:true */
/* global RSAKey:true */

var CONFIG_PAT = {
    enforceEmailVerification: Match.Optional(Boolean)
};

EncryptionUtils = {
    /**
     * standard options
     */
    options: {
        enforceEmailVerification: true
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
            newDoc = {};

        // encrypt the desired fields
        _.each(fields, function (field) {
            newDoc[field] = self.symEncryptWithKey(doc[field],
                documentKey);
        });

        // get the principal of the user
        var userPrincipal = self.getPrincipal('user', user._id);
        if (!userPrincipal) {
            console.warn('no user principal found');
            return;
        }
        // fetch a potential existing principal
        // - this might be the case in a update
        var existingPrincipal = Principals.findOne({
            dataType: name,
            dataId: doc._id
        });
        // collect users that currently have access to the document
        var shareWithUsers = [];
        if (existingPrincipal) {
            // find all users that had access to the encrypted data
            shareWithUsers = _.map(existingPrincipal.encryptedPrivateKeys,
                function (obj) {
                    return obj.userId;
                });
            // filter out the owner, so he does not get readded
            shareWithUsers = _.filter(shareWithUsers, function (userId) {
                return userId !== user._id;
            });
            // remove the old principal
            Principals.remove({
                _id: existingPrincipal._id
            });
        }
        // encrypt the document key with the users public key -- needs to be RSA
        var encryptedDocumentKey = self.asymEncryptWithKey(documentKey,
            userPrincipal.publicKey);

        // create the principle in the database
        Principals.insert({
            dataType: name,
            dataId: doc._id,
            encryptedPrivateKeys: [{
                userId: user._id,
                key: encryptedDocumentKey
            }]
        });

        // re-share the document
        _.each(shareWithUsers, function (userId) {
            self.shareDocWithUser(doc._id, name, userId);
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
        var decryptedPrincipalPrivateKey = self.getDocumentKeyOfPrincipal(
            principal, true);
        // return if something went wrong
        if (!decryptedPrincipalPrivateKey) {
            return doc;
        }
        // decrypt each given field
        _.each(fields, function (field) {
            if (doc.hasOwnProperty(field)) {
                doc[field] = self.symDecryptWithKey(doc[field],
                    decryptedPrincipalPrivateKey);
            }
        });
        // set encrypted to false for better ui state handling
        doc.encrypted = false;

        return doc;
    },
    /**
     * encrypts the given message asymmetrically with the given (public) key
     * @param message - the message to be encrypted
     * @param key - the public key that is used to encrypt the message
     */
    asymEncryptWithKey: function (message, key) {
        var rsaKey = new RSA(key);
        return rsaKey.encrypt(message, 'base64');
    },
    /**
     * encrypts the given message symmetrically with the given  key
     * @param message - the message to be encrypted
     * @param key - key that is used to en-/decrypt the message
     */
    symEncryptWithKey: function (message, key) {
        var encryptedMessage = CryptoJS.AES.encrypt(message, key);
        return encryptedMessage.toString();
    },
    /**
     * decrypts the given message asymmetrically with the given (private) key
     * @param message - the message to be decrypted
     * @param key - the private key that is used to decrypt the message
     */
    asymDecryptWithKey: function (message, key) {
        var rsaKey = new RSA(key);
        return rsaKey.decrypt(message, 'utf8');
    },
    /**
     * decrypts the given message symmetrically with the given  key
     * @param message - the message to be decrypted
     * @param key - key that is used to en-/decrypt the message
     */
    symDecryptWithKey: function (message, key) {
        var decryptedMessage = CryptoJS.AES.decrypt(message, key);
        return decryptedMessage.toString(CryptoJS.enc.Utf8);
    },
    /**
     * generates a random key which may be used for symmetric crypto
     */
    generateRandomKey: function () {

        if (window.secureShared && window.secureShared.generatePassphrase) {
            return CryptoJS.lib.WordArray.random(16).toString();
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
            privateKey = Session.get('privateKey'),
            encryptedKeys = _.where(principal.encryptedPrivateKeys,
                searchObj);

        if (!encryptedKeys.length) {
            return;
        }
        // return decrypted key
        return self.asymDecryptWithKey(encryptedKeys[0].key, privateKey);
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
        var self = this;
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
        // get the decrypted key that was used to encrypt the document
        var documentKey = self.getDocumentKeyOfPrincipal(
            documentPrincipal);
        // encrypted the document key with the public key of the user that
        // the document should be shared with
        var encryptedDocumentKey = self.asymEncryptWithKey(documentKey,
            userPrincipal.publicKey);

        // update the principal
        Principals.update({
            _id: documentPrincipal._id
        }, {
            $push: {
                encryptedPrivateKeys: {
                    userId: userId,
                    key: encryptedDocumentKey
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
    extendProfile: function (password, callback) {
        var self = this;
        var userId = Meteor.userId();
        // generate keypair
        var key = new RSAKey();
        // generate a 2048 bit key async
        key.generateAsync(2048, "03", function () {
            var unencryptedPrivateKey = key.privatePEM();
            // store the raw private key in the session
            Session.setAuth('privateKey', unencryptedPrivateKey);
            // encrypt the user's private key
            var privateKey = self.symEncryptWithKey(
                unencryptedPrivateKey, password);

            // use meteor call since the client might/should not be allowd
            // to update the user document client-side
            Meteor.call('storeEncryptedPrivateKey', privateKey);
            // add a principal for the user
            Principals.insert({
                dataType: 'user',
                dataId: userId,
                publicKey: key.publicPEM()
            });

            if (callback) {
                callback();
            }
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
            var privateKey = self.symDecryptWithKey(user.profile.privateKey,
                password);
            Session.setAuth('privateKey', privateKey);
        } else {
            console.info('no private key found -> generating one now');
            // if not it is probably his first login -> generate keypair
            self.extendProfile(password);
        }
    }
};
