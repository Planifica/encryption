Package.describe({
  name: 'planifica:encryption',
  version: '0.0.1',
  // Brief, one-line summary of the package.
  summary: '',
  // URL to the Git repository containing the source code for this package.
  git: '',
  // By default, Meteor will default to using README.md for documentation.
  // To avoid submitting documentation, set this field to null.
  documentation: 'README.md'
});

Package.onUse(function(api) {
  api.versionsFrom('1.1.0.2');

  api.use(['underscore', 'check', 'reactive-var'], 'client');
  api.use('u2622:persistent-session@0.4.1', 'client');
  api.use('aldeed:simple-schema');
  api.use('ongoworks:security');
  api.use('matb33:collection-hooks@0.7.13');
  api.use('robertlowe:persistent-reactive-dict');

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
