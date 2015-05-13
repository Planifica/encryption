// Write your package code here!
Encryption = {
  // encrypts a doc with the given configuration
  encryptDoc: function(doc, fields, name){
    var self = this;
    // client only so this works :)
    var user = Meteor.user();
    // generate a id for the document in order to have one bevore inserting it
    doc._id = new Meteor.Collection.ObjectID()._str;
    // use a 2048 bit rsa key
    var key = new RSA({b: 512});
    // create public and private keys for the post principal
    var publicKey = key.exportKey('public');
    var privateKey = key.exportKey('private');

    // encrypt the message with the public key of the post principal
    _.each(fields, function(field){
      doc[field] = key.encrypt(doc[field], 'base64');
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
      encryptedPrivateKeys: [
        {
          userId: user._id,
          key: privateKey
        }
      ]
    });
  },

  // decrypts a doc with the given configuration
  decryptDoc: function(doc, fields, name){
    var self = this;
    // get principal
    var principal = self.getPrincipal(name, doc._id);
    // return if the doc was not encrypted correctly
    if(!principal){
      return doc;
    }
    // get decrypted private key of principal
    var decryptedPrincipalPrivateKey = self.getPrivateKeyOfPrincipal(principal);
    // return if something went wrong
    if(!decryptedPrincipalPrivateKey){
      return doc;
    }
    // decrypt each given field
    _.each(fields, function(field){
      doc[field] = self.decryptWithRsaKey(doc[field], decryptedPrincipalPrivateKey);
    });
    return doc;
  },
  // encrypts the given message with a key
  encryptWithRsaKey: function(message, key){
    var userKey = new RSA(key);
    return userKey.encrypt(message, 'base64');
  },
  // decrypts the given message with a key
  decryptWithRsaKey: function(message, key){
    var postKey = new RSA(key);
    return postKey.decrypt(message, 'utf8');
  },
  // get private key of given principal
  getPrivateKeyOfPrincipal: function(principal){
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
  getPrincipal: function(type, id){
    return Principals.findOne({ownerType: type, ownerId: id});
  },
  shareDocWithUser: function(docId, docType, userId) {
    var self = this;
    // find principal of user to share post with
    var userPrincipal = self.getPrincipal('user', userId);
    if(!userPrincipal){
        console.warn('no principal found for user with id: '+userId);
        return;
    }

    // fint principal of post
    var principal = self.getPrincipal(docType, docId);
    if(!principal){
      console.warn('no principal found for '+docType+' with id: '+docId);
      return;
    }
    var principalKey = self.getPrivateKeyOfPrincipal(principal);

    var key = self.encryptWithRsaKey(principalKey, userPrincipal.publicKey);

    Principals.update({
      _id: principal._id
    },{$push: {
        encryptedPrivateKeys: {
          userId: userId, key: key
        }
    }});
  },
  extendProfile: function(password){

    // generate keypair
    var key = new RSA({b: 512});
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
  }
};
