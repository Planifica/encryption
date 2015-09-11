Package.describe({
  name: 'planifica:encryption',
  version: '0.0.4',
  // Brief, one-line summary of the package.
  summary: 'Client-Side Encryption for Mongo Collections',
  // URL to the Git repository containing the source code for this package.
  git: 'https://github.com/Planifica/encryption',
  // By default, Meteor will default to using README.md for documentation.
  // To avoid submitting documentation, set this field to null.
  documentation: 'README.md'
});

Package.onUse(function(api) {
  api.versionsFrom('1.1.0.2');

  api.use(['underscore', 'check'], 'client');
  api.use('u2622:persistent-session@0.4.1', 'client');
  api.use('aldeed:collection2@2.5.0');
  api.use('ongoworks:security@1.2.0');
  api.use('matb33:collection-hooks@0.7.13', 'client');
  api.use('robertlowe:persistent-reactive-dict@0.1.2', 'client');
  api.use('jparker:crypto-core@0.1.0', 'client');
  api.use('jparker:crypto-base64@0.1.0', 'client');

  api.addFiles('tweetnacl-js-master/nacl-fast.min.js', 'client');

  api.addFiles('principals.js', ['client', 'server']);
  api.addFiles('server.js', 'server');
  api.addFiles('utils.js', 'client');
  api.addFiles('EncryptionUtils.js', 'client');
  api.addFiles('CollectionEncryption.js', 'client');

  api.export('CollectionEncryption');
  api.export('EncryptionUtils');
  api.export('Principals');
});

Package.onTest(function(api) {
  api.use('tinytest');
  api.use('planifica:encryption');
});
