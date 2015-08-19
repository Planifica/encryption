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

Meteor.publish("principals", function (partnerId) {
    if (partnerId) {
        // subscribe to all own principals and the user principal of the partner
        return Principals.find({
            $or: [{
                dataId: partnerId
            }, {
                ownerId: this.userId
            }, {
                'encryptedPrivateKeys.userId': this.userId
            }]
        });
    }
    // subscribe to all own principals
    return Principals.find({
        $or: [{
            ownerId: this.userId
        }, {
            'encryptedPrivateKeys.userId': this.userId
        }]
    });
});
