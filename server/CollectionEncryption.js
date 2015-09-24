CollectionEncryption = function (collection, fields) {
  var self = this;
  // create a new instance of the mongo collection
  self.collection = collection;

  // store the properties
  self.fields = fields;
  // check if simple schema is being used
  if (_.isFunction(collection.simpleSchema) && !!collection.simpleSchema()) {
      self._initSchema();
      self.schema = self.collection.simpleSchema();
  }
};

_.extend(CollectionEncryption.prototype, collectionEncryptionBase);
