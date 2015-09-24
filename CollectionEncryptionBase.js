collectionEncryptionBase = {
    /**
     * returns the key of the encrypted field
     * that indicates whether the doc is in encrypted or decrypted form
     */
    getEncryptedFieldKey: function () {
        var self = this,
            encryptedFieldKey = 'encrypted';

        if (self.collection === Meteor.users) {
            encryptedFieldKey = 'profile.encrypted';
        }
        return encryptedFieldKey;
    },
    /**
     * addes the encrypted property to the schema of the collection
     */
    _initSchema: function () {
        var self = this,
            schema = {},
            fieldKey = self.getEncryptedFieldKey(),
            currentSchema = {};

        // check if the collection already has a schema
        if (_.isFunction(self.collection.simpleSchema)) {
            currentSchema = self.collection.simpleSchema()._schema;
        }
        // check if the existing schema already defines a the field
        if (!!currentSchema[fieldKey]) {
            // prevent overwriting of field
            return;
        }

        // init the encryption schema for the given collection client-side
        schema[fieldKey] = {
            type: Boolean,
            defaultValue: false
        };

        console.log(schema);
        // attach the schema
        self.collection.attachSchema(schema);
    }
};
