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
    // delete existing principal
    var existingPrincipal = Principals.findOne({
      dataType: name,
      dataId: doc._id
    });
    var shareWithUsers = [];
    if (existingPrincipal) {
      // find all users that had access to the encrypted data
      shareWithUsers = _.map(existingPrincipal.encryptedPrivateKeys, function(obj){
        return obj.userId;
      });
      // filter out the owner, so he does not get readded
      shareWithUsers = _.filter(shareWithUsers, function(userId) {
        return userId !== user._id;
      });
      // remove the old principal
      Principals.remove({_id: existingPrincipal._id});
    }
    // encrypt the private key with the users public key
    privateKey = self.encryptWithRsaKey(privateKey, userPrincipal.publicKey);
    // create the principle in the database
    Principals.insert({
      dataType: name,
      dataId: doc._id,
      publicKey: publicKey,
      encryptedPrivateKeys: [{
        userId: user._id,
        key: privateKey
      }]
    });

    _.each(shareWithUsers, function(userId){
      self.shareDocWithUser(doc._id, name, userId);
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
      dataType: type,
      dataId: id
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
  extendProfile: function (password, callback) {
    var userId = Meteor.userId();
    // generate keypair
    var key = new RSAKey();
    // generate a 1024 bit key async
    key.generateAsync(1024, "03", function () {
      // store the raw private key in the session
      Session.setAuth('privateKey', key.privatePEM());
      // encrypt the user's private key
      var privateKey = CryptoJS.AES.encrypt(key.privatePEM(), password);

      Meteor.call('storeEncryptedPrivateKey', privateKey.toString());
      // add a principal for the user
      Principals.insert({
        dataType: 'user',
        dataId: userId,
        publicKey: key.publicPEM()
      });

      callback();
    });

  },
  onSignIn: function(password) {
    var user = Meteor.user();
    var privateKey = CryptoJS.AES.decrypt(user.profile.privateKey, password);
    Session.setAuth('privateKey', privateKey.toString(CryptoJS.enc.Utf8));
  }
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
  self._listenToInserts();
  // listen to before update and after update events
  self._listenToUpdates();
  // listen to after remove events
  self._listenToRemove();
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
      if(!doc){
        return;
      }
      if(!doc.encrypted){
        return;
      }
      EncryptionUtils.decryptDoc(doc, self.fields, self.principalName);
    });
  },
  /**
   * listen to insert operations on the given collection in order to encrypt
   * automtically
   */
  _listenToInserts: function () {
    var self = this;

    self.collection.before.insert(function(userId, doc) {
      self.startDocEncryption(userId, doc);
    });

    self.collection.after.insert(function() {
      self.finishDocEncryption(this);
    });
  },
  /**
   * listen to update operations on the given collection in order to encrypt
   * automtically
   */
  _listenToUpdates: function () {
    var self = this;

    self.collection.before.update(function(userId, doc, fieldNames, modifier) {
      var decryptedDoc = self.collection.findOne({_id: doc._id});
      modifier = self.startDocUpdate(userId, decryptedDoc, fieldNames, modifier);
    });

    self.collection.after.update(function(userId, doc) {
      self.finishDocEncryption(doc);
    });
  },
  /**
   * listen to remove operations on the given collection in order to remove
   * the corresponding principal
   */
  _listenToRemove: function() {
    var self = this;

    self.collection.after.remove(function(userId, doc) {
      // find the corresponding principal
      var principal = Principals.findOne({dataId: doc._id});
      // if there is a principal then remove it
      if (principal) {
        Principals.remove({_id: principal._id});
      }
    });
  },
  /**
   * starts the encryption of a document by removing the content
   * that should be encrypted
   * gets called before insert
   * @param userId
   * @param doc - the doc that should be encrypted
   */
  startDocEncryption: function(userId, doc) {
    var self = this;

    doc.encrypted = false;
    // incase of a collection update we have a _id here which is not
    // in the schema
    if(doc.hasOwnProperty('_id')){
      delete doc._id;
    }
    // check if doc matches the schema
    if (!Match.test(doc, self.schema)) {
      return doc;
    }
    // tell the encryption package what data needs to encrypted next
    EncryptionUtils.docToUpdate = _.clone(doc);
    // unset fields that will be encrypted
    _.each(self.fields, function (field) {
      doc[field] = '--';
    });

    // unload warning while generating keys
    $(window).bind('beforeunload', function () {
      return 'Encryption will fail if you leave now!';
    });
    return doc;
  },
  /**
   * starts the encryption of a document by removing the content
   * that should be encrypted
   * gets called before update
   * @param userId
   * @param doc - the doc that should be encrypted
   */
  startDocUpdate: function(userId, doc, fieldNames, modifier) {
    var self = this;
    var needsEncryption = false;
    modifier.$set = modifier.$set || {};

    // check if a field that should be encrypted was edited
    _.each(self.fields, function (field) {
      if(modifier.$set.hasOwnProperty(field)){
        // store the modified state for later encryption
        doc[field] = modifier.$set[field];
        // remove the UNencrypted information before storing into the db
        modifier.$set[field] = '--';
        needsEncryption = true;
      }
    });
    if(!needsEncryption){
      return;
    }else{
      modifier.$set.encrypted = false;
    }
    // tell the encryption package what data needs to encrypted next
    EncryptionUtils.docToUpdate = _.clone(doc);
    // unload warning while generating keys
    $(window).bind('beforeunload', function () {
      return 'Encryption will fail if you leave now!';
    });

    return modifier;
  },
  /**
   * starts the async key generation for the document and updates the encrypted
   * fields in the collection
   * called after insert and update
   * @param doc - the doc that should be encrypted
   */
  finishDocEncryption: function(doc) {
    var self = this;

    if(!doc._id) {
      return;
    }
    var key = new RSAKey();
    // generate a 1024 bit key async
    key.generateAsync(1024, "03", function () {
      // store keypair
      EncryptionUtils.setKeypair(key.privatePEM(), key.publicPEM());
      // get encrypted doc
      var encryptedDoc = EncryptionUtils.encryptDocWithId(
        doc._id, self.fields, self.principalName);

      encryptedDoc.encrypted = true;

      // update doc with encrypted fields
      // use direct in order to circumvent any defined hooks
      self.collection.direct.update({
        _id: doc._id
      }, {
        $set: encryptedDoc
      });
      // unbind unload warning
      $(window).unbind('beforeunload');
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
