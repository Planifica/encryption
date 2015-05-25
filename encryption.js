/* global EncryptionUtils:true */
/* global CollectionEncryption:true */
/* global RSAKey:true */

EncryptionUtils = {
  docToUpdate: {},
  setKeypair: function (privateKey, publicKey) {
    var self = this;
    self.keyPairForNextEncryption = {
      privateKey: privateKey,
      publicKey: publicKey
    };
  },
  // encrypts a doc with the given configuration
  encryptDocWithId: function (docId, fields, name) {
    var self = this;
    // client only so this works :)
    var user = Meteor.user();
    // get stored doc
    var doc = self.docToUpdate;
    // generate a id for the document in order to have one bevore inserting it
    doc._id = docId;
    var key = new RSA(self.keyPairForNextEncryption.privateKey);
    // create public and private keys for the post principal
    var publicKey = key.exportKey('public');
    var privateKey = key.exportKey('private');

    // encrypt the message with the public key of the post principal
    var newDoc = {};
    _.each(fields, function (field) {
      newDoc[field] = key.encrypt(doc[field], 'base64');
    });

    // get the principal of the user
    var userPrincipal = self.getPrincipal('user', user._id);
    if (!userPrincipal) {
      return;
    }
    // encrypt the private key with the users public key
    privateKey = self.encryptWithRsaKey(privateKey, userPrincipal.publicKey);
    // create the principle in the database
    Principals.insert({
      ownerType: name,
      ownerId: doc._id,
      publicKey: publicKey,
      encryptedPrivateKeys: [{
        userId: user._id,
        key: privateKey
      }]
    });
    return newDoc;
  },

  // decrypts a doc with the given configuration
  decryptDoc: function (doc, fields, name) {
    var self = this;
    // get principal
    var principal = self.getPrincipal(name, doc._id);
    // return if the doc was not encrypted correctly
    if (!principal) {
      return doc;
    }
    // get decrypted private key of principal
    var decryptedPrincipalPrivateKey = self.getPrivateKeyOfPrincipal(
      principal);
    // return if something went wrong
    if (!decryptedPrincipalPrivateKey) {
      return doc;
    }
    // decrypt each given field
    _.each(fields, function (field) {
      doc[field] = self.decryptWithRsaKey(doc[field],
        decryptedPrincipalPrivateKey);
    });
    return doc;
  },
  // encrypts the given message with a key
  encryptWithRsaKey: function (message, key) {
    var userKey = new RSA(key);
    return userKey.encrypt(message, 'base64');
  },
  // decrypts the given message with a key
  decryptWithRsaKey: function (message, key) {
    var postKey = new RSA(key);
    return postKey.decrypt(message, 'utf8');
  },
  // get private key of given principal
  getPrivateKeyOfPrincipal: function (principal) {
    var self = this,
      user = Meteor.user(),
      searchObj = {
        userId: user._id
      },
      privateKey = Session.get('privateKey'),
      encryptedKeys = _.where(principal.encryptedPrivateKeys, searchObj);

    if (!encryptedKeys.length) {
      return;
    }
    // return decrypted key
    return self.decryptWithRsaKey(encryptedKeys[0].key, privateKey);
  },
  // search if a principal for the given params exists
  getPrincipal: function (type, id) {
    return Principals.findOne({
      ownerType: type,
      ownerId: id
    });
  },
  shareDocWithUser: function (docId, docType, userId) {
    var self = this;
    // find principal of user to share post with
    var userPrincipal = self.getPrincipal('user', userId);
    if (!userPrincipal) {
      console.warn('no principal found for user with id: ' + userId);
      return;
    }

    // fint principal of post
    var principal = self.getPrincipal(docType, docId);
    if (!principal) {
      console.warn('no principal found for ' + docType + ' with id: ' +
        docId);
      return;
    }
    var principalKey = self.getPrivateKeyOfPrincipal(principal);

    var key = self.encryptWithRsaKey(principalKey, userPrincipal.publicKey);

    Principals.update({
      _id: principal._id
    }, {
      $push: {
        encryptedPrivateKeys: {
          userId: userId,
          key: key
        }
      }
    });
  },
  extendProfile: function (password) {

    // generate keypair
    var key = new RSA({
      b: 1024
    });
    // export public and private key
    var publicKey = key.exportKey('public');
    var privateKey = key.exportKey('private');
    // encrypt the user's private key
    var encryptedPrivateKey = CryptoJS.AES.encrypt(privateKey, password);

    function callback(userId) {
      // add a principal for the user
      Principals.insert({
        ownerType: 'user',
        ownerId: userId,
        publicKey: publicKey
      });
    }

    // return private key and callback
    return {
      profileExtension: {
        privateKey: encryptedPrivateKey.toString()
      },
      callback: callback
    };
  },
};

/**
 * register a collection to encrypt/decrypt automtically
 * @param collection - the collection instance
 * @param fields - array of fields which will be encrypted
 */
CollectionEncryption = function (collection, name, fields, schema) {
  var self = this;
  // create a new instance of the mongo collection
  self.collection = collection;
  // store the properties
  self.fields = fields;
  self.schema = schema;
  self.principalName = name + 'Principal';

  // listen to findOne events from the database
  self._listenToFinds();
  // listen to before insert and after insert events
  self._listeToInserts();
};

_.extend(CollectionEncryption.prototype, {
  /**
   * listen to findOne operations on the given collection in order to decrypt
   * automtically
   */
  _listenToFinds: function () {
    var self = this;

    self.collection.after.findOne(function (userId, selector, options,
      doc) {
      if (!Meteor.user()) {
        return;
      }
      EncryptionUtils.decryptDoc(doc, self.fields, self.principalName);
    });
  },
  /**
   * listen to insert operations on the given collection in order to encrypt
   * automtically
   */
  _listeToInserts: function () {
    var self = this;

    self.collection.before.insert(function (userId, doc) {
      // check if doc matches the schema
      if (!Match.test(doc, self.schema)) {
        return false;
      }
      // tell the encryption package what data needs to encrypted next
      EncryptionUtils.docToUpdate = _.clone(doc);
      // unset fields that will be encrypted
      _.each(self.fields, function (field) {
        doc[field] = '';
      });

      // unload warning while generating keys
      $(window).bind('beforeunload', function () {
        return 'Encryption will fail if you leave now!';
      });
    });

    self.collection.after.insert(function () {
      var postId = this._id;
      var key = new RSAKey();
      // generate a 1024 bit key async
      key.generateAsync(1024, "03", function () {
        // store keypair
        EncryptionUtils.setKeypair(key.privatePEM(), key.publicPEM());
        // get encrypted doc
        var encryptedDoc = EncryptionUtils.encryptDocWithId(
          postId, self.fields, self.principalName);
        // update doc with encrypted fields
        self.collection.update({
          _id: postId
        }, {
          $set: encryptedDoc
        });
        // ui feedback
        // Materialize.toast(TAPi18n.__('postInsertedSuccessfully'), 4000);
        // unbind unload warning
        $(window).unbind('beforeunload');
      });
    });
  },
  /**
   * shares the doc with the given id with the user with the given id
   */
  shareDocWithUser: function (docId, userId) {
    var self = this;
    EncryptionUtils.shareDocWithUser(docId, self.principalName, userId);
  }
});
