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

  api.use(['underscore', 'planifica:node-rsa', 'jparker:crypto-aes'], 'client');
  api.use('u2622:persistent-session@=0.3.3', 'client');
  api.imply(['planifica:node-rsa', 'jparker:crypto-aes']);

  // rsa
  api.addFiles('jsbn-master/base64.js', 'client');
  api.addFiles('jsbn-master/ec.js', 'client');
  api.addFiles('jsbn-master/jsbn.js', 'client');
  api.addFiles('jsbn-master/jsbn2.js', 'client');
  api.addFiles('jsbn-master/prng4.js', 'client');
  api.addFiles('jsbn-master/rng.js', 'client');
  api.addFiles('jsbn-master/rsa.js', 'client');
  api.addFiles('jsbn-master/rsa2.js', 'client');
  api.addFiles('jsbn-master/sec.js', 'client');
  api.addFiles('jsbn-master/sha1.js', 'client');

  // rsa async
  api.addFiles('rsasync-master/rsasync.js', 'client');

  api.addFiles('encryption.js', 'client');

  api.export('CollectionEncryption');
  api.export('EncryptionUtils');
});

Package.onTest(function(api) {
  api.use('tinytest');
  api.use('planifica:encryption');
});
