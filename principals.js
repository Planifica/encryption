this.Principals = new Meteor.Collection("principals");

var Schema = {};
Schema.Principal = new SimpleSchema({
  ownerType: {
    type: String
  },
  ownerId: {
    type: String
  },
  publicKey: {
    type: String
  },
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

Meteor.users.attachSchema({
  // gets encrypted with the users password
  'profile.privateKey': {
    type: String,
    optional: true
  }
});
