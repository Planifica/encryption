Principals = new Meteor.Collection("principals");

var Schema = {};
Schema.Principal = new SimpleSchema({
  dataType: {
    type: String
  },
  dataId: {
    type: String
  },
  ownerId: {
    type: String
  },
  publicKey: {
    type: String,
    optional: true
  },
  privateKey: {
    type: String,
    optional: true
  },
  /**
   * the nonce that is used for the symmetric encryption of the document
   */
  nonce: {
    type: String,
    optional: true
  }
  encryptedPrivateKeys: {
    type: [Object],
    optional: true
  },
  'encryptedPrivateKeys.$.userId': {
    type: String
  },
  'encryptedPrivateKeys.$.key': {
    type: String
  },
  /**
   * the nonces that are used for the asymmetric encryption of the document key
   */
  'encryptedPrivateKeys.$.nonce': {
    type: String
  }
});

Principals.attachSchema(Schema.Principal);

Principals.before.insert(function(userId, doc){
  doc.ownerId = userId;
  return doc;
});

if (Meteor.users.simpleSchema()) {
  Meteor.users.attachSchema({
    // gets encrypted with the users password
    'profile.privateKey': {
      type: String,
      optional: true
    }
  });
}
