Dachcom.OpenID
==============
Adds OpenID authentication to TYPO3 Neos

Installation
------------
Add composer dependency.
Add route handling for this plugin to your Routes.yaml:

```
-
  name: 'Dachcom OpenID'
  uriPattern: '<DachcomOpenID>'
  subRoutes:
    'DachcomOpenID':
      package: 'Dachcom.OpenID'
      variables:
        'defaultUriSuffix': '.html'
```

Configuration
-------------
Extend your Settings.yaml with the user-identity mapping

```
Dachcom:
  OpenID:
    users:
      -
        alias: admin
        identity: http://admin.openid-provider.com/
```

Usage
-----
Open your browser and point it to the OpenID login page (http://your-host.tld/dachcom.openid)

Planned Features
----------------
* user-identity mapping in backend
