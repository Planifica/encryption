Meteor.methods({
    storeEncryptedPrivateKey: function (encryptedKey) {
        Meteor.users.update({
            _id: this.userId
        }, {
            $set: {
                'profile.privateKey': encryptedKey
            }
        });
    }
});

Security.defineMethod("ifCurrentUserIsOwner", {
    fetch: [],
    transform: null,
    deny: function (type, arg, userId, doc) {
        return userId !== doc.ownerId;
    }
});

Principals.permit(['insert']).apply();

Principals.permit(['update', 'remove'])
    .never().apply();

Principals.permit(['update', 'remove'])
    .ifLoggedIn()
    .ifCurrentUserIsOwner()
    .apply();

Meteor.publish("principals", function() {
	return Principals.find({
    ownerId: this.userId
  });
});
