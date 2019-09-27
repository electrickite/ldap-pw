PHP LDAP Password Change
========================

A simple PHP script to change an LDAP account password.

Assumptions
-----------

This script makes quite a few assumptions in the name of simplicity:

  1. Your LDAP server uses password authentication
  2. User accounts can change their own password
  3. Password changes are performed using extended operations (exop)
  4. Both the front-end HTTP and back-end LDAP connections will use some form of
     transport security. While this is not required, failure to secure either
     connection will result in credentials being transmitted in the clear.
  5. You are using OpenLDAP 2.4. Other LDAP servers may work just fine, but have
     not been tested.

Requirements
------------

  * A web server configured to execute PHP scripts (Apache, nginx, etc.)
  * PHP 7.2+
  * PHP LDAP functions available
  * PHP OpenSSL functions available

Installation
------------

  1. Configure your web server to serve the `public` directory. DO NOT expose
     the root project directory as it contains potentially sensitive
     configuration files.
  2. Copy `config.example.php` to `config.php`
  3. Edit `config.php` as appropriate for your environment. Note that
     `LDAP_URL`, `LDAP_BASE_DN`, and `ENCRYPTION_KEY` must all be defined.

During initial testing it may be helpful to deine `LDAP_DEBUG` as `true` to
enable in-browser LDAP log messages. This should be set to `false` in
production.

Copyright and License
---------------------

Copyright 2019 Corey Hinshaw

This software is made available under the MIT license as described in the
LICENSE file.
