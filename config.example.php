<?php

/* Required configuration */
define('LDAP_URL', 'ldap://ldap.example.com');
define('LDAP_BASE_DN', 'dc=example,dc=com');
define('ENCRYPTION_KEY', 'secret');

/* Optional configuration */
//define('LDAP_DN_TEMPLATE', 'uid=???,ou=people,dc=example,dc=com');
//define('LDAP_BIND_DN', 'cn=auth,dc=example,dc=com');
//define('LDAP_BIND_PW', 'secret');
//define('LDAP_FILTER', '(&(objectclass=person)(uid=???))');
//define('LDAP_VERSION', 3);
//define('LDAP_STARTTLS', false);
//define('LDAP_CACERT', '/path/to/cacert.pem');
//define('ENCRYPTION_CIPHER', 'aes-128-ctr');
