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
        var schema = {},
            collection = Mongo.Collection.get(collectionName),
            currentSchema = {};

        // check if the collection already has a schema
        if (_.isFunction(collection.simpleSchema)) {
            currentSchema = collection.simpleSchema()._schema;
        }
        // check if the existing schema already defines a the field
        if (!!currentSchema[fieldKey]) {
            // prevent overwriting of field
            throw new Meteor.Error(
                "Not-allowed",
                "You are not allowed to overwrite this field"
            );
        }

        schema[fieldKey] = {
            type: Boolean,
            // set the default value to false to indicate that no document
            // is encrypted by default
            defaultValue: false
        };
        // add ecrypted field to the collection schema
        collection.attachSchema(schema);
    }
});

Security.defineMethod("ifCurrentUserIsOwner", {
    fetch: ['ownerId'],
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
