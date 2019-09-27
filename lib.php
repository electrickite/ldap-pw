<?php
require 'config.php';

if (!defined('LDAP_DEBUG')) {
    define('LDAP_DEBUG', false);
}
if (!defined('ENCRYPTION_CIPHER')) {
    define('ENCRYPTION_CIPHER', 'aes-128-ctr');
}


class FormState {
    const INIT = 'Init';
    const LOGIN = 'Login';
    const UPDATE = 'Update';
    const SUCCESS = 'Success';
    const FAILURE = 'Failure';

    protected $state = self::INIT;
    protected $msg;

    protected $states = [
        self::INIT => [
            'submit' => self::LOGIN,
            'title' => 'Login',
        ],
        self::LOGIN => [
            'submit' => self::LOGIN,
            'title' => 'Login',
        ],
        self::UPDATE => [
            'submit' => self::UPDATE,
            'title' => 'Update Password',
        ],
        self::SUCCESS => [
            'submit' => self::SUCCESS,
            'title' => 'Password Updated',
        ],
        self::FAILURE => [
            'submit' => self::FAILURE,
            'title' => 'Update Failed',
        ],
    ];

    public function setState($state) {
        if (in_array($state, array_keys($this->states))) {
            $this->state = $state;
        }
    }

    public function setMessage($msg) {
        $this->msg = $msg;
    }

    public function state() {
        return $this->state;
    }

    public function complete() {
        return $this->state == self::SUCCESS || $this->state == self::FAILURE;
    }

    public function message() {
        return $this->msg;
    }

    public function submit() {
        return $this->states[$this->state]['submit'];
    }

    public function title() {
        return $this->states[$this->state]['title'];
    }
}


function encryptToken($username, $password) {
    $timestamp = time();
    $data = serialize([$username, $password, $timestamp]);
    $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length(ENCRYPTION_CIPHER));
    return openssl_encrypt($data, ENCRYPTION_CIPHER, ENCRYPTION_KEY, 0, $iv) . "::" . bin2hex($iv);
}

function decryptToken($token) {
    list($ciphertext, $iv) = explode("::", $token);
    $data = openssl_decrypt($ciphertext, ENCRYPTION_CIPHER, ENCRYPTION_KEY, 0, hex2bin($iv));
    if ($data !== false) {
        $data = unserialize($data);
        if (is_array($data)) {
            return $data;
        }
    }
    return [null, null, 0];
}

function authenticate($username, $password) {
    $link = bind($username, $password);
    if ($link === false) {
        return false;
    } else {
        @ldap_close($link);
        return true;
    }
}

function changePassword($username, $password, $new_password) {
    $link = bind($username, $password);
    if ($link === false) {
        return false;
    }

    if (@ldap_exop_passwd($link, null, $password, $new_password)) {
        print_debug("Password successfully updated for: $username");
        @ldap_close($link);
        return true;
    } else {
        handle_ldap_error($link, "Password change failed for: $username");
        return false;
    }
}

function bind($username, $password) {
    $conf = loadConfig();

    $link = connect($conf);
    if ($link === false) {
        print_debug('Could not complete connection to LDAP server');
        return false;
    }

    if ($conf['dn_template']) {
        $user_dn = str_replace('???', ldap_escape($username, '', LDAP_ESCAPE_DN), $conf['dn_template']);
    } else {
        $user_dn = dnFromUsername($link, $conf, $username);
        if ($user_dn === false) {
            return false;
        }
    }

    $bind = @ldap_bind($link, $user_dn, $password);
    if ($bind === true) {
        print_debug('LDAP authentication successful for: ' . $username);
        return $link;
    } else {
        handle_ldap_error($link, 'LDAP authentication failed for: ' . $username);
        return false;
    }
}

function loadConfig() {
    $conf = array();

    foreach (array('LDAP_URL', 'LDAP_BASE_DN') as $setting) {
        if (!defined($setting)) {
            print_debug("$setting configuration is required");
            return false;
        }
    }

    $parsedUri = parse_url(LDAP_URL);
    if ($parsedUri === false) {
        print_debug('Could not parse LDAP server URL');
        return false;
    }
    $conf['host'] = $parsedUri['host'];
    $conf['scheme'] = $parsedUri['scheme'];

    if (is_int($parsedUri['port'])) {
        $conf['port'] = $parsedUri['port'];
    } else {
        $conf['port'] = ($conf['scheme'] === 'ldaps') ? 636 : 389;
    }

    $conf['base_dn'] = LDAP_BASE_DN;
    $conf['dn_template'] = defined('LDAP_DN_TEMPLATE') ? LDAP_DN_TEMPLATE : null;
    $conf['bind_dn'] = defined('LDAP_BIND_DN') ? LDAP_BIND_DN : null;
    $conf['bind_pw'] = defined('LDAP_BIND_PW') ? LDAP_BIND_PW : null;
    $conf['version'] = defined('LDAP_VERSION') ? intval(LDAP_VERSION) : 3;
    $conf['starttls'] = defined('LDAP_STARTTLS') ? boolval(LDAP_STARTTLS) : false;
    $conf['filter'] = defined('LDAP_FILTER') ? LDAP_FILTER : '(&(objectclass=person)(uid=???))';

    if (defined('LDAP_CACERT')) {
        putenv('LDAPTLS_CACERT='.LDAP_CACERT);
    }

    return $conf;
}

function connect($conf) {
    $link = @ldap_connect($conf['host'], $conf['port']);
    if ($link === false) {
        print_debug('Connection parameters invalid. Host: '.$conf['host'].' Port: '.$conf['port']);
        return false;
    }

    if (!@ldap_set_option($link, LDAP_OPT_PROTOCOL_VERSION, $conf['version'])) {
        handle_ldap_error($link, 'Failed to set LDAP protocol version to ' . $conf['version']);
        return false;
    }

    if (!@ldap_set_option($link, LDAP_OPT_REFERRALS, false)) {
        handle_ldap_error($link, 'Could not disable LDAP referrals');
        return false;
    }

    if ($conf['starttls'] && !@ldap_start_tls($link)) {
        handle_ldap_error($link, 'Could not set STARTTLS');
        return false;
    }

    print_debug('Connection prepared for LDAP server: ' . $conf['host']);
    return $link;
}

function dnFromUsername($link, $conf, $username) {
    if (!@ldap_bind($link, $conf['bind_dn'], $conf['bind_pw'])) {
        if ($conf['bind_dn']) {
            handle_ldap_error($link, 'LDAP bind falied for DN: ' . $conf['bind_dn']);
        } else {
            handle_ldap_error($link, 'Anonymous LDAP bind failed');
        }
        return false;
    }
    print_debug('LDAP search bind successful');

    $filter = str_replace('???', ldap_escape($username, '', LDAP_ESCAPE_FILTER), $conf['filter']);
    $results = @ldap_search($link, $conf['base_dn'], $filter, array($conf['login_attr']));
    if ($results === false) {
        handle_ldap_error($link, 'LDAP search failed in base DN ' . $conf['base_dn'] . ' using filer ' . $filter);
        return false;
    }

    $count = @ldap_count_entries($link, $results);
    if ($count != 1) {
        if ($count > 1) {
            print_debug('Multple LDAP entries found for username ' . $username);
        } else {
            print_debug('LDAP user not found: ' . $username);
        }
        @ldap_close($link);
        return false;
    }

    $user = @ldap_first_entry($link, $results);
    if ($user === false) {
        handle_ldap_error($link, 'Error retrieving LDAP entry for: ' . $username);
        return false;
    }
    $user_dn = @ldap_get_dn($link, $user);
    if ($user_dn == false) {
        handle_ldap_error($link, 'Error retrieving DN for LDAP entry');
        return false;
    }

    print_debug('LDAP search found matching DN: ' . $user_dn);
    return $user_dn;
}

function handle_ldap_error($link, $msg) {
    $err = ldap_errno($link);
    print_debug($msg);
    print_debug("LDAP Error ${err}: " . ldap_err2str($err));
    @ldap_close($link);
}

function print_debug($msg) {
    if (defined('LDAP_DEBUG') && LDAP_DEBUG) {
        echo $msg . "\n";
    }
}
