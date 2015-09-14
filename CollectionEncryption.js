/* global CollectionEncryption:true */
/* global EncryptionUtils:true */

var CONFIG_PAT = Match.Optional({
    /**
     * gets called once a key is generated
     * should be defiend by the user
     * @param privateKey
     * @param publicKey
     * @param document
     */
    onKeyGenerated: Match.Optional(Function),
    /**
     * gets called once a document is inserted and encrypted
     * should be defiend by the user
     * @param document - the encrypted document
     */
    onFinishedDocEncryption: Match.Optional(Function)
});

/**
 * register a collection to encrypt/decrypt automtically
 * @param collection - the collection instance
 * @param fields - array of fields which will be encrypted
 * @param config
 */
CollectionEncryption = function (collection, fields, config) {
    var self = this;

    // check if the config is valid
    check(config, CONFIG_PAT);

    var options = _.omit(config);
    self.config = _.defaults(options, self.config);

    // create a new instance of the mongo collection
    self.collection = collection;

    // store the properties
    self.fields = fields;
    // check if simple schema is being used
    if (_.isFunction(collection.simpleSchema) && !!collection.simpleSchema()) {
        self._initSchema();
        self.schema = self.collection.simpleSchema();
    }
    // build up the name of the principal using the collection name
    self.principalName = collection._name + 'Principal';
    self.docsToEncrypt = [];

    // listen to findOne events from the database
    self._listenToFinds();
    // listen to before insert and after insert events
    self._listenToInserts();
    // listen to before update and after update events
    self._listenToUpdates();
    // listen to after remove events
    self._listenToRemove();
};

_.extend(CollectionEncryption.prototype, {
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
            schema = {};

        // init the encryption schema for the given collection client-side
        schema[self.getEncryptedFieldKey()] = {
            type: Boolean,
            defaultValue: false
        };
        // attach the schema
        self.collection.attachSchema(schema);

        // tell server to init the encryption schema for the given collection
        Meteor.call(
            'initEncryptionSchema',
            self.collection._name,
            self.getEncryptedFieldKey()
        );
    },
    /**
     * listen to findOne operations on the given collection in order to decrypt
     * automtically
     */
    _listenToFinds: function () {
        var self = this;

        // listen to findOne events
        self.collection.after.findOne(function (userId, selector,
            options, doc) {
            doc = self._decryptDoc(doc);
        });
    },
    /**
     * decrypts the given doc and stores it into minimongo
     * @param doc
     */
    _decryptDoc: function (doc) {
        var self = this;
        if (!doc) {
            return;
        }
        // if the doc already is decrypted, don't do anything
        if (doc[self.getEncryptedFieldKey()] === false) {
            return;
        }
        // otherwise decrypt the document
        doc = EncryptionUtils.decryptDoc(doc, self.fields,
            self.principalName, self.getEncryptedFieldKey());

        return doc;
    },
    /**
     * listen to insert operations on the given collection in order to encrypt
     * automtically
     */
    _listenToInserts: function () {
        var self = this;

        // listen to the before insert, since we need to
        // set some properties on the document before inserting
        // like unsetting the fields that shall be encrypted
        self.collection.before.insert(function (userId, doc) {
            self.startDocEncryption(userId, doc);
        });

        // listen to after insert, so we can encrypt the document async
        self.collection.after.insert(function (userId, doc) {
            self.finishDocEncryption(doc);
        });
    },
    /**
     * listen to update operations on the given collection in order to (re)encrypt
     * automtically
     */
    _listenToUpdates: function () {
        var self = this;

        self.collection.before.update(function (userId, doc,
            fieldNames, modifier) {
            // change the modifier, so that the fields that shall be encrypted
            // do not get stored in the db unencrypted
            modifier = self.startDocUpdate(userId,
                doc, fieldNames, modifier);
        });

        self.collection.after.update(function (userId, doc) {
            // trigger the actual encryption
            self.finishDocEncryption(doc);
        });
    },
    /**
     * listen to remove operations on the given collection in order to remove
     * the corresponding principal
     */
    _listenToRemove: function () {
        var self = this;

        // once a document gets removed we also remove the corresponding principal
        self.collection.after.remove(function (userId, doc) {
            // find the corresponding principal
            var principal = Principals.findOne({
                dataId: doc._id
            });
            // if there is a principal then remove it
            if (principal) {
                Principals.remove({
                    _id: principal._id
                });
            }
        });
    },
    /**
     * starts the encryption of a document by removing the content
     * that should be encrypted
     * gets called before insert
     * @param userId
     * @param doc - the doc that should be encrypted
     */
    startDocEncryption: function (userId, doc) {
        var self = this;

        doc[self.getEncryptedFieldKey()] = false;
        // in case of a collection update we have a _id here which is not
        // in the (potential) schema
        if (doc.hasOwnProperty('_id')) {
            delete doc._id;
        }
        // check if doc matches the schema
        if (self.schema && !Match.test(doc, self.schema)) {
            // if the document does not match the schema we stop before encrypting
            // since collection2 will deny the db insert anyway
            return doc;
        }
        // tell the encryption package what data needs to encrypted next
        self._storeDocToEncrypt(doc);
        // unset fields that will be encrypted
        _.each(self.fields, function (field) {
            if (!!doc[field]) {
                // for now we use -- to indicate that this field is still to be encrypted
                // however this should never be visible in the UI since doc.encrypted
                // can be used to wait for the fully decrypted document
                doc[field] = '--';
            }
        });

        // unload warning while generating keys
        $(window).bind('beforeunload', function () {
            return 'Encryption will fail if you leave now!';
        });

        return doc;
    },
    /**
     * starts the encryption of a document by removing the content
     * that should be encrypted
     * gets called before update
     * @param userId
     * @param doc - the doc that should be encrypted
     * @param fieldNames - the names of the fields that got modified
     * @param modifier - the actual mongo modifier we need to adapt
     */
    startDocUpdate: function (userId, doc, fieldNames, modifier) {
        var self = this;
        var needsEncryption = false;
        modifier.$set = modifier.$set || {};

        // check if a field that should be encrypted was edited
        _.each(self.fields, function (field) {
            var fieldValue = modifier.$set[field];
            if (!!fieldValue) {
                // store the modified state for later encryption
                doc[field] = fieldValue;
                // remove the UNencrypted information before storing into the db
                modifier.$set[field] = '--';
                needsEncryption = true;
            }
        });

        // check if fields that need to be encrypted were modified
        if (!needsEncryption) {
            // if so just return the modifier - we have no need to adapt it
            return modifier;
        }
        modifier.$set[self.getEncryptedFieldKey()] = false;
        // tell the encryption package what data needs to encrypted next
        self._storeDocToEncrypt(doc);
        // unload warning while generating keys
        $(window).bind('beforeunload', function () {
            return 'Encryption will fail if you leave now!';
        });

        return modifier;
    },
    /**
     * starts the async key generation for the document and updates the encrypted
     * fields in the collection
     * called after insert and update
     * @param doc - the doc that should be encrypted, which does not contain the
     *              values that should be encrypted, but holds the _id
     */
    finishDocEncryption: function (doc) {
        var self = this,
            docToEncrypt = self._getDocToEncrypt();

        // check if there is something to encrypt
        if (!doc._id || !docToEncrypt) {
            return;
        }
        // generate a random key for the document
        var documentKey = EncryptionUtils.generateRandomKey();

        // call the callback once the key is encrypted
        if (self.config.onKeyGenerated) {
            self.config.onKeyGenerated(documentKey, docToEncrypt);
        }
        // restore the document with its _id as it was before the insert
        docToEncrypt._id = doc._id;
        Meteor.subscribe('principals', docToEncrypt._id, function () {
            // get encrypted doc
            var encryptedDoc = EncryptionUtils.encryptDocWithId(
                docToEncrypt, self.fields, self.principalName,
                documentKey);

            // the document is encrypted now and may be shown in the UI
            encryptedDoc[self.getEncryptedFieldKey()] =
                true;

            if (encryptedDoc) {
                // update doc with encrypted fields
                // use direct in order to circumvent any defined hooks
                self.collection.direct.update({
                    _id: doc._id
                }, {
                    $set: encryptedDoc
                });
            }
            if (self.config.onFinishedDocEncryption) {
                self.config.onFinishedDocEncryption(doc);
            }
            // unbind unload warning
            $(window).unbind('beforeunload');
        });
    },
    /**
     * shares the doc with the given id with the user with the given id
     */
    shareDocWithUser: function (docId, userId) {
        var self = this;
        EncryptionUtils.shareDocWithUser(docId, self.principalName,
            userId);
    },
    /**
     * stores the docs that need to be encrypted
     */
    _storeDocToEncrypt: function (doc) {
        var self = this;
        self.docsToEncrypt.push(_.clone(doc));
    },
    /**
     * return that oldest doc that was queued for encryption
     * TODO this might be harmful when inserting multiple documents at once
     * since they might get misordered
     */
    _getDocToEncrypt: function () {
        var self = this;
        return self.docsToEncrypt.pop();
    }
});
