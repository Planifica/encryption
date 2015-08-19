/* global CollectionEncryption:true */
/* global EncryptionUtils:true */
/* global RSAKey:true */

/**
 * register a collection to encrypt/decrypt automtically
 * @param collection - the collection instance
 * @param fields - array of fields which will be encrypted
 * @param schema - the schema used for the collection
 * @param asyncCrypto: Boolean - wether to use RSA(true) or AES(false)
 */
CollectionEncryption = function (collection, name, fields, schema, asyncCrypto) {
  var self = this;
  self.asyncCrypto = asyncCrypto !== false;
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

  /*
   * gets called once a key is generated
   * should be defiend by the user
   * @param privateKey
   * @param publicKey
   * @param document
   */
  onKeyGenerated: function ( /* privateKey, publicKey, document */ ) {},
  /*
   * gets called once a document is inserted and encrypted
   * should be defiend by the user
   * @param document - the encrypted document
   */
  finishedInsertWithEncryption: function ( /* document */ ) {},
  /**
   * listen to findOne operations on the given collection in order to decrypt
   * automtically
   */
  _listenToFinds: function () {
    var self = this;

    self.collection.after.find(function (userId, selector, options, cursor) {
      if (!Meteor.user()) {
        return;
      }
      cursor.forEach(function(doc){
        if (!doc) {
          return;
        }
        if (!doc.encrypted) {
          return;
        }
        EncryptionUtils.decryptDoc(doc, self.fields,
          self.principalName, self.asyncCrypto);

          // update the document in the client side minimongo
          var copyDoc = _.omit(doc, '_id');
          self.collection._collection.update({_id: doc._id}, {
            $set: copyDoc
          });
      });
    });
  },
  /**
   * listen to insert operations on the given collection in order to encrypt
   * automtically
   */
  _listenToInserts: function () {
    var self = this;

    self.collection.before.insert(function (userId, doc) {
      self.startDocEncryption(userId, doc);
    });

    self.collection.after.insert(function (userId, doc) {
      self.finishDocEncryption(doc);
    });
  },
  /**
   * listen to update operations on the given collection in order to encrypt
   * automtically
   */
  _listenToUpdates: function () {
    var self = this;

    self.collection.before.update(function (userId, doc,
      fieldNames, modifier) {
      var decryptedDoc = self.collection.findOne({
        _id: doc._id
      });
      modifier = self.startDocUpdate(userId,
        decryptedDoc, fieldNames, modifier);
    });

    self.collection.after.update(function (userId, doc) {
      self.finishDocEncryption(doc);
    });
  },
  /**
   * listen to remove operations on the given collection in order to remove
   * the corresponding principal
   */
  _listenToRemove: function () {
    var self = this;

    self.collection.after.remove(function (userId, doc) {
      // find the corresponding principal
      var principal = Principals.findOne({
        dataId: doc._id
      });
      // if there is a principal then remove it
      if (principal) {
        Principals.remove({
          _id: principal._id
        });
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
  startDocEncryption: function (userId, doc) {
    var self = this;

    doc.encrypted = false;
    // incase of a collection update we have a _id here which is not
    // in the schema
    if (doc.hasOwnProperty('_id')) {
      delete doc._id;
    }
    // check if doc matches the schema
    if (!Match.test(doc, self.schema)) {
      // console.log(check(doc, self.schema));
      return doc;
    }
    // tell the encryption package what data needs to encrypted next
    EncryptionUtils.docToUpdate = _.clone(doc);
    // unset fields that will be encrypted
    _.each(self.fields, function (field) {
      if (doc.hasOwnProperty('field')) {
        doc[field] = '--';
      }
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
  startDocUpdate: function (userId, doc, fieldNames, modifier) {
    var self = this;
    var needsEncryption = false;
    modifier.$set = modifier.$set || {};

    // check if a field that should be encrypted was edited
    _.each(self.fields, function (field) {
      if (modifier.$set.hasOwnProperty(field)) {
        // store the modified state for later encryption
        doc[field] = modifier.$set[field];
        // remove the UNencrypted information before storing into the db
        modifier.$set[field] = '--';
        needsEncryption = true;
      }
    });

    if (!needsEncryption) {
      return modifier;
    } else {
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
  finishDocEncryption: function (doc) {
    var self = this;

    if (!doc._id || !EncryptionUtils.docToUpdate) {
      return;
    }
    self.generateKey(function (privateKey, publicKey) {
      if (_.isFunction(self.onKeyGenerated)) {
        self.onKeyGenerated(privateKey, publicKey,
          EncryptionUtils.docToUpdate);
      }
      // store keypair
      EncryptionUtils.setKeypair(privateKey,
        publicKey);
      // get encrypted doc
      var encryptedDoc = EncryptionUtils.encryptDocWithId(
        doc._id, self.fields, self.principalName,
        self.asyncCrypto);

      encryptedDoc.encrypted = true;

      // update doc with encrypted fields
      // use direct in order to circumvent any defined hooks
      self.collection.direct.update({
        _id: doc._id
      }, {
        $set: encryptedDoc
      });
      if (_.isFunction(self.finishedInsertWithEncryption)) {
        self.finishedInsertWithEncryption(doc);
      }
      // unbind unload warning
      $(window).unbind('beforeunload');
      EncryptionUtils.docToUpdate = null;
    });
  },
  generateKey: function (callback) {
    var self = this;
    var key = null;
    if (self.asyncCrypto === true) {
      key = new RSAKey();
      // generate a 1024 bit key async
      key.generateAsync(1024, "03", function () {
        callback(key.privatePEM(), key.publicPEM());
      });
    } else {
      if (window.secureShared && window.secureShared.generatePassphrase) {
        key = CryptoJS.lib.WordArray.random(16).toString();
        callback(key);
      }
    }
  },
  /**
   * shares the doc with the given id with the user with the given id
   */
  shareDocWithUser: function (docId, userId) {
    var self = this;
    EncryptionUtils.shareDocWithUser(docId, self.principalName,
      userId);
  }
});
