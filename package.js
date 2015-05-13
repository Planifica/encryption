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

  api.use(['planifica:node-rsa', 'jparker:crypto-aes'], 'client');
  api.imply(['planifica:node-rsa', 'jparker:crypto-aes']);

  api.addFiles('encryption.js', 'client');

  api.export('Encryption');
});

Package.onTest(function(api) {
  api.use('tinytest');
  api.use('planifica:encryption');
});
