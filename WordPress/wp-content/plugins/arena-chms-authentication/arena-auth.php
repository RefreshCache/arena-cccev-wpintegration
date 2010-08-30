<?php
/*
Plugin Name: Arena ChMS Authentication Provider
Plugin URI: http://redmine.refreshcache.com/projects/cccevwpintegration
Description: This plugin will provide some basic user authentication against your Arena ChMS installation.
Version: 0.9.0
Author: Jason Offutt
Author URI: http://twitter.com/jasonoffutt
License: GPL2
*/

/*  Copyright 2010 Arena ChMS Authentication Provider  (email : jason.offutt@cccev.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

if (!class_exists("ArenaAuthenticationPlugin")) {

    class ArenaAuthenticationPlugin {
        var $adminOptionsName = 'ArenaAuthenticationAdminOptions';

        var $auth_service_path_setting = 'arena_authentication_service_path';
        var $org_id_setting = 'arena_org_id';
        var $arena_roles = 'arena_security_roles';
        var $wp_default_role = 'default_wordpress_role';

        var $isAuthenticated = false;

        function ArenaAuthenticationPlugin() { }

        /**
         * Registers plugin options with WP database.
         * Should only fire on plugin activation
         */
        public function init() {
            $this->load_options();
        }

        /**
	 * Wrapper function
	 *
	 * @param $arg1 WP_User or username
	 * @param $arg2 username or password
	 * @param $arg3 passwprd or empty
	 * @return WP_User
	 */
        public function authenticate($arg1 = NULL, $arg2 = NULL, $arg3 = NULL) {
            global $wp_version;

            if (version_compare($wp_version, '2.8', '>=')) {
                return $this->arena_authenticate($arg1, $arg2, $arg3);
            }

            return $this->arena_authenticate(NULL, $arg1, $arg2);
        }

        /**
         * This is where the real heavy lifting happens. Take user input and attempt to authenticate
         * against Arena Authentication web service.
         */
        public function arena_authenticate($user = NULL, $username = '', $password = '') {
            $this->isAuthenticated = false;
            $userID = NULL;
            
            // case insensitive matching on username
            $username = strtolower($username);
            $options = $this->load_options();

            if ($username != '' AND $password != '') {

                $params = array(
                    'username' => $username,
                    'password' => $password,
                    'ipAddress' => $_SERVER['REMOTE_ADDR'],
                    'securityRoles' => $options[$this->arena_roles],
                    'orgID' => $options[$this->org_id_setting]
                );

                try {
                    // http://arena-install-path/WebServices/Custom/CCCEV/Core/AuthenticationService.asmx?WSDL
                    $client = new SoapClient($options[$this->auth_service_path_setting] . '?WSDL');
                    $soapResult = $client->AuthenticateWP($params);
                    $result = $soapResult->AuthenticateWPResult->enc_value;

                    //echo '<pre>';
                    //print_r($soapResult);
                    //echo '</pre>';

                    // Check if authentication failed
                    // @todo: add setting for admin users to bypass Arena security
                    if (!property_exists($soapResult, 'AuthenticateWPResult') AND !$this->is_admin($username)) {
                        $this->display_error($username);
                        die();
                    }

                    $user = get_userdatabylogin($username);

                    // If user does not exist in WP database, create one
                    if (!$user) {
                        $email = $result->Email;
                        $first_name = $result->FirstName;
                        $last_name = $result->LastName;
                        $display_name = $result->DisplayName;
                        $user_id = $this->create_user($username, $password, $email, $first_name, $last_name, $display_name, $options[$this->wp_default_role]);
                    }

                    // load user object
                    if (!$user_id) {
                        require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR .'registration.php');
                        $user_id = username_exists($username);
                    }

                    $user = new WP_User($user_id);
                    $this->isAuthenticated = true;
                    return $user;
                }
                catch (Exception $ex) {
                    return false;
                }
            }

            return false;
        }

        /**
         * If no user exists in the WP database matching the Arena user, we'll create one automatically
         */
        public function create_user($username, $password, $email, $first_name, $last_name, $display_name, $default_role = '') {
            
            global $wp_version;

            require_once(ABSPATH . WPINC . DIRECTORY_SEPARATOR . 'registration.php');

            // Here we go!
            $return = wp_create_user($username, $password, $email);

            $user_id = username_exists($username);

            // log errors
            if (is_wp_error($return)) {
                echo $return->get_error_message();
                die();
            }

            if ( !$user_id ) {
                die("Error creating user!");
            }
            else {
                if (version_compare($wp_version, '3', '>=')) {
                    // WP 3.0 and above
                    update_user_meta($user_id, 'first_name', $first_name);
                    update_user_meta($user_id, 'last_name', $last_name);
                }
                else {
                    // WP 2.x
                    update_usermeta($user_id, 'first_name', $first_name);
                    update_usermeta($user_id, 'last_name', $last_name);
                }

                // set display_name
                if ($display_name != '') {
                    $return = wp_update_user(array('ID' => $user_id, 'display_name' => $display_name));
                }

                // set role
                if ( $default_role != '' ) {
                    $return = wp_update_user(array("ID" => $user_id, "role" => strtolower($default_role)));
                }
            }

            return $user_id;
        }

        public function override_password_check($check, $password, $hash, $user_id) {
		
            if ($this->isAuthenticated == true) {
                return true;
            }
            else {
                return $check;
            }
	}

        public function load_options() {

            $options = array(
                $this->auth_service_path_setting => '',
                $this->org_id_setting => '',
                $this->arena_roles => '',
                $this->wp_default_role => ''
            );

            $devOptions = get_option($this->adminOptionsName);

            if (!empty($devOptions)) {
                foreach ($devOptions as $key => $option) {
                    $options[$key] = $option;
                }
            }

            update_option($this->adminOptionsName, $options);
            return $options;
        }

        protected function is_admin($username) {
            global $wpdb;
            $admin_role = 'administrator';
            $user = get_userdatabylogin($username);
            $roles = $user->{$wpdb->prefix . 'capabilities'};

            if (array_key_exists($admin_role, $roles)) {
                return true;
            }

            return false;
        }


        protected function display_error($username) {
            ?>
<html>
    <head>
        <title><?php bloginfo('name'); ?> &rsaquo; <?php echo $title; ?></title>
	<meta http-equiv="Content-Type" content="<?php bloginfo('html_type'); ?>; charset=<?php bloginfo('charset'); ?>" />
        <?php
	wp_admin_css( 'login', true );
	wp_admin_css( 'colors-fresh', true );
	do_action('login_head'); ?>
    </head>
    <body>
        <div id="login"><h1><a href="<?php echo apply_filters('login_headerurl', 'http://wordpress.org/'); ?>" title="<?php echo apply_filters('login_headertitle', __('Powered by WordPress')); ?>"><?php bloginfo('name'); ?></a></h1>
            <div id="login_error">
                <h2>Oops!</h2>
                <p>Looks like you might not have permission to edit this blog. If you feel you're being blocked in error, please <a href="mailto:webologists@cccev.com">let us know</a>. Thanks!</p>
            </div>
        </div>
    </body>
</html>
            <?php
        }

        public function print_admin_page() {

            $options = $this->load_options();

            if (isset($_POST['update_arenaAuthenticatoinPluginSettings'])) {
                if (isset($_POST['authServicePath'])) {
                    $options[$this->auth_service_path_setting] = apply_filters('content_save_pre', $_POST['authServicePath']);
                }
                if (isset($_POST['orgID'])) {
                    $options[$this->org_id_setting] = apply_filters('content_save_pre', $_POST['orgID']);
                }

                if (isset($_POST['securityRoles'])) {
                    $options[$this->arena_roles] = apply_filters('content_save_pre', $_POST['securityRoles']);
                }

                if (isset($_POST['defaultRole'])) {
                    $options[$this->wp_default_role] = apply_filters('content_save_pre', $_POST['defaultRole']);
                }

                update_option($this->adminOptionsName, $options);
                ?>
            <div class="updated">
                <p><strong><?php _e("Settings Updated.", "ArenaAuthenticationPlugin"); ?></strong></p>
            </div>
            <?php
            } ?>

            <div class="wrap">
                <form method="post" action="<?php echo $_SERVER['REQUEST_URI']; ?>">
                    <h2>Arena Authentication Plugin</h2>
                    <table>
                        <tr>
                            <td><p><label for="authServicePath">Arena Authentication Service Path: </label></p></td>
                            <td><input type="text" id="authServicePath" name="authServicePath" value="<?php echo $options[$this->auth_service_path_setting]; ?>" /></td>
                        </tr>
                        <tr>
                            <td>
                                <p><label for="orgID">Organization ID: </label></p>
                            </td>
                            <td>
                                <input type="text" id="orgID" name="orgID" value="<?php echo $options[$this->org_id_setting] ?>" />
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <p><label for="securityRoles">Security Roles: </label></p>
                            </td>
                            <td>
                                <input type="text" id="securityRoles" name="securityRoles" value="<?php echo $options[$this->arena_roles]; ?>" />
                            </td>
                        </tr>
                        <tr>
                            <td>
                                <p><label for="defaultRole">Default WordPress Role: </label></p>
                            </td>
                            <td>
                                <input type="text" id="defaultRole" name="defaultRole" value="<?php echo $options[$this->wp_default_role]; ?>" />
                            </td>
                        </tr>
                    </table>
                    <div class="submit">
                        <input type="submit" name="update_arenaAuthenticatoinPluginSettings" value="<?php _e("Update Settings", "ArenaAuthenticationPlugin"); ?>"
                    </div>
                </form>
            </div>
            <?php
        }

        public function disable_function() {
            die('Disabled');
        }
    }

    $arena_auth = new ArenaAuthenticationPlugin();
}
?>

<?php // Inline Scripts
    if (isset($arena_auth)) {
        // Actions
        add_action('activate_arena-chms-authentication/arena-auth.php', array(&$arena_auth, 'init'));
        add_action('admin_menu', 'ArenaAuth_ap');

        // WP 2.8 and above?
        if (version_compare($wp_version, '2.8', '>=')) {
            add_filter('authenticate', array(&$arena_auth, 'authenticate'), 10, 3);
        }
        else {
            add_action('wp_authenticate', array(&$arena_auth, 'authenticate'), 10, 2);
        }

        // Kill certain authentication behavior, since Arena will handle authentication
        add_action('lost_password', array(&$arena_auth, 'disable_function'));
        add_action('retrieve_password', array(&$arena_auth, 'disable_function'));
        add_action('password_reset', array(&$arena_auth, 'disable_function'));

        // Override base WP authentication
        add_filter('check_password', array(&$arena_auth, 'override_password_check'), 10, 4);
    }

    if (!function_exists('ArenaAuth_ap')) {
        function ArenaAuth_ap() {
            global $arena_auth;

            if (!isset($arena_auth)) {
                return;
            }

            if (function_exists('add_options_page')) {
                add_options_page('Arena Authentication', 'Arena Authentication', 9, basename(__FILE__), array(&$arena_auth, 'print_admin_page'));
            }
        }
    }
?>