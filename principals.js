this.Principals = new Meteor.Collection("principals");

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
  // this is used for sharing data
  // TODO find better name than encryptedPrivateKeys
  encryptedPrivateKeys: {
    type: [Object],
    optional: true
  },
  'encryptedPrivateKeys.$.userId': {
    type: String
  },
  'encryptedPrivateKeys.$.key': {
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
