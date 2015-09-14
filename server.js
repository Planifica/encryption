Meteor.methods({
    storeEncryptedPrivateKey: function (encryptedKey) {
        Meteor.users.update({
            _id: this.userId
        }, {
            $set: {
                'profile.privateKey': encryptedKey
            }
        });
    },
    initEncryptionSchema: function (collectionName, fieldKey) {
        var schema = {};
        schema[fieldKey] = {
            type: Boolean,
            defaultValue: false
        };
        // add ecrypted field to the collection schema
        Mongo.Collection.get(collectionName).attachSchema(schema);
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

Meteor.publish("principals", function (dataId) {
    if (dataId) {
        // subscribe to all own principals and the user principal of the partner
        return Principals.find({
            $or: [{
                dataId: dataId
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
