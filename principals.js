Principals = new Meteor.Collection("principals");

var SchemaPrincipal = new SimpleSchema({
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
    type: Uint8Array,
    optional: true
  },
  privateKey: {
    type: Uint8Array,
    optional: true
  },
  /**
   * the nonce that is used for the symmetric encryption of the document
   */
  symNonce: {
    type: Uint8Array,
    optional: true
  },
  addedPasswordBytes: {
    type: Uint8Array,
    optional: true
  },
  encryptedPrivateKeys: {
    type: [Object],
    optional: true
  },
  'encryptedPrivateKeys.$.userId': {
    type: String
  },
  'encryptedPrivateKeys.$.key': {
    type: Uint8Array
  },
  /**
   * the nonces that are used for the asymmetric encryption of the document key
   */
  'encryptedPrivateKeys.$.asymNonce': {
    type: Uint8Array
  }
});

Principals.attachSchema(SchemaPrincipal);

Principals.before.insert(function(userId, doc){
  doc.ownerId = userId;
  return doc;
});
