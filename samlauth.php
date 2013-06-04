<?php
/*
Plugin Name: SAML 2.0 Single Sign-On
Version: 0.8.7
Plugin URI: http://keithbartholomew.com
Description: Authenticate users using <a href="http://rnd.feide.no/simplesamlphp">simpleSAMLphp</a>.
Author: Keith Bartholomew
Author URI: http://keithbartholomew.com
*/

$upload_dir = wp_upload_dir();
define('SAMLAUTH_CONF', $upload_dir['basedir'] . '/saml-20-single-sign-on/etc');
define('SAMLAUTH_ROOT',dirname(__FILE__));
define('SAMLAUTH_URL',plugins_url() . '/' . basename( dirname(__FILE__) ) );

class SamlAuth
{
  private $saml;
  private $opt;
  private $secretsauce;
  
  function __construct()
  {
    if(! get_option('saml_authentication_options') )
    {
    	$this->opt = array(
			'enabled' => false,
			'idp' => 'https://your-idp.net',
			'nameidpolicy' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
			'username_attribute' => 'http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname',
			'firstname_attribute' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
			'lastname_attribute' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
			'email_attribute' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
			'groups_attribute' => 'http://schemas.xmlsoap.org/claims/Group',
			'super_admin_group' => '',
			'admin_group' => '',
			'editor_group' => '',
			'author_group' => '',
			'contributor_group' => '',
			'subscriber_group' => '',
			'allow_unlisted_users' => true
		);
      	
      	update_option('saml_authentication_options',$this->opt);
  
    }
    $this->opt = get_option('saml_authentication_options');
    if(is_array($this->opt))
    {
      require_once(constant('SAMLAUTH_ROOT') . '/saml/lib/_autoload.php');
			if($this->opt['enabled'])
			{
				$this->saml = new SimpleSAML_Auth_Simple((string)get_current_blog_id());
				
				add_action('wp_authenticate',array($this,'authenticate'));
		      	add_action('wp_logout',array($this,'logout'));
			}
    }
    
    // Hash to generate password for SAML users.
    // This is never actually used by the user, but we need to know what it is, and it needs to be consistent
    
    // WARNING: If the WP AUTH_KEY is changed, all SAML users will be unable to login! In cases where this is
    //   actually desired, such as an intrusion, you must delete SAML users or manually set their passwords.
    //   it's messy, so be careful!

    $this->secretsauce = constant('AUTH_KEY');
    $this->set_environment();
  }
  
  public function authenticate()
  {
    $this->saml->requireAuth( array('ReturnTo' => get_admin_url() ) );
      $attrs = $this->saml->getAttributes();
      $username = $attrs[$this->opt['username_attribute']][0];
      if(get_user_by('login',$username))
      {
        $this->simulate_signon($username);
      }
      else
      {
        $this->new_user($attrs);
      }
  }
  
  public function logout()
  {
    $this->saml->logout(wp_logout_url( get_settings('siteurl') ));
  }
  
  private function new_user($attrs)
  {
    $login = $attrs[$this->opt['username_attribute']][0];
    $email = $attrs[$this->opt['email_attribute']][0];
    $first_name = $attrs[$this->opt['firstname_attribute']][0];
    $last_name = $attrs[$this->opt['lastname_attribute']][0];
    $display_name = $first_name . ' ' . $last_name;
    
    $role = $this->update_role();
    
    if( $role !== FALSE )
    {
      $user_opts = array(
        'user_login' => $login ,
        'user_pass'  => $this->user_password($login,$this->secretsauce) ,
        'user_email' => $email ,
        'first_name' => $first_name ,
        'last_name'  => $last_name ,
        'display_name' => $display_name ,
        'role'       => $role
        );
      wp_insert_user($user_opts);
      $this->simulate_signon($login);
    }
    else
    {
      die('The website administrator has not given you permission to log in.');
    }
  }
  
  private function simulate_signon($username)
  {
    remove_filter('wp_authenticate',array($this,'authenticate'));
    
    $this->update_role();
    
    $login = array(
      'user_login' => $username,
      'user_password' => $this->user_password($username,$this->secretsauce),
      'remember' => false
    );
    
    $result = wp_signon($login,true);
    if(is_wp_error($result))
    {
      echo $result->get_error_message();
      exit();
    }
    else
    {
      wp_redirect(get_admin_url());
      exit();
    }
  }
  
  private function update_role()
  {
    $attrs = $this->saml->getAttributes();
    if( in_array($this->opt['admin_group'],$attrs[$this->opt['groups_attribute']]) )
    {
      $role = 'administrator';
    }
    elseif( in_array($this->opt['editor_group'],$attrs[$this->opt['groups_attribute']]) )
    {
      $role = 'editor';
    }
    elseif( in_array($this->opt['author_group'],$attrs[$this->opt['groups_attribute']]) )
    {
      $role = 'editor';
    }
    elseif( in_array($this->opt['contributor_group'],$attrs[$this->opt['groups_attribute']]) )
    {
      $role = 'editor';
    }
    elseif( in_array($this->opt['subscriber_group'],$attrs[$this->opt['groups_attribute']]) )
    {
      $role = 'editor';
    }
    elseif( $this->opt['allow_unlisted_users'])
    {
      $role = 'subscriber';
    }
    else
    {
      $role = FALSE;
    }
    
    $user = get_user_by('login',$attrs[$this->opt['username_attribute']]);
    if($user)
    {
      $user->set_role($role);
    }
    
    return $role;
  }
  
  private function user_password($value,$key)
  {
    $hash = hash_hmac('sha256',$value,$key);
    return $hash;
  }
  
  private function set_environment()
  {
  	if(! file_exists( constant('SAMLAUTH_CONF') ) )
  	{
  		mkdir( constant('SAMLAUTH_CONF'), 0775, true );
  	}
  	
  	if(! file_exists( constant('SAMLAUTH_CONF') . '/certs') )
  	{
  		mkdir( constant('SAMLAUTH_CONF') . '/certs', 0775, true );
  	}
  	
  	if(! file_exists( constant('SAMLAUTH_CONF') . '/config' ) )
  	{
  		mkdir( constant('SAMLAUTH_CONF') . '/config' , 0775, true );
  	}
  	
  	if(! file_exists(constant('SAMLAUTH_CONF') . '/config/saml20-idp-remote.ini') )
  	{
  		file_put_contents(constant('SAMLAUTH_CONF') . '/config/saml20-idp-remote.ini',"[https://your-idp.net]\nname = Your IdP\nSingleSignOnService = https://your-idp.net/SSOService\nSingleLogoutService = https://your-idp.net/SingleLogoutService\ncertFingerprint = 0000000000000000000000000000000000000000");
  	}
  	
  	if(! file_exists( constant('SAMLAUTH_CONF') . '/certs/.htaccess' ) )
  	{
  		file_put_contents( constant('SAMLAUTH_CONF') . '/certs/.htaccess' , 'Deny from all' );
  	}
  }
  
} // End of Class SamlAuth

$Saml = new SamlAuth();

function show_password_fields($show_password_fields) {
  return false;
}

function disable_function() {
  die('Disabled');
}

// WordPress action hooks
	add_action('lost_password', 'disable_function');
	add_action('retrieve_password', 'disable_function');
	add_action('password_reset', 'disable_function');
	add_filter('show_password_fields', 'show_password_fields');
	add_action('init','saml_menus');


//----------------------------------------------------------------------------
//    ADMIN OPTION PAGE FUNCTIONS
//----------------------------------------------------------------------------

/* $saml_opts = array(
    'enabled' => false,
	'idp' => '',
	'nameidpolicy' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
	'username_attribute' => 'http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname',
    'firstname_attribute' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
    'lastname_attribute' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
    'email_attribute' => 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
    'groups_attribute' => 'http://schemas.xmlsoap.org/claims/Group',
    'super_admin_group' => '',
    'admin_group' => '',
    'editor_group' => '',
    'author_group' => '',
    'contributor_group' => '',
    'subscriber_group' => '',
    'allow_unlisted_users' => true
  ); */

function saml_menus()
{
	if( is_multisite() )
	{	
		add_action('network_admin_menu', 'saml_idp_menus');
		add_action('admin_menu', 'saml_sp_menus');
	}
	else
	{
		add_action('admin_menu', 'saml_idp_menus');
		add_action('admin_menu', 'saml_sp_menus');
	}
}

function saml_idp_menus()
{
	if( is_multisite() )
	{
		add_submenu_page('settings.php', 'Single Sign-On', 'Single Sign-On', 'manage_network', 'sso_idp.php', 'sso_idp');
		add_submenu_page('settings.php', 'Single Sign-On', 'Single Sign-On', 'manage_network', 'sso_help.php', 'sso_help');
		
		remove_submenu_page( 'settings.php', 'sso_help.php' );
	}
	else
	{
		add_submenu_page('options-general.php', 'Single Sign-On', 'Single Sign-On', 'administrator', 'sso_idp.php', 'sso_idp');
		add_submenu_page('options-general.php', 'Single Sign-On', 'Single Sign-On', 'administrator', 'sso_help.php', 'sso_help');
		
		remove_submenu_page( 'options-general.php', 'sso_idp.php' );
		remove_submenu_page( 'options-general.php', 'sso_help.php' );
	}
}

function saml_sp_menus()
{
	add_submenu_page('options-general.php', 'Single Sign-On', 'Single Sign-On', 'administrator', 'sso_general.php', 'sso_general');
	add_submenu_page('options-general.php', 'Single Sign-On', 'Single Sign-On', 'administrator', 'sso_sp.php', 'sso_sp');
	add_submenu_page('options-general.php', 'Single Sign-On', 'Single Sign-On', 'administrator', 'sso_help.php', 'sso_help');
	
	remove_submenu_page( 'options-general.php', 'sso_sp.php' );
	remove_submenu_page( 'options-general.php', 'sso_help.php' );
}

function sso_general(){
  include(constant('SAMLAUTH_ROOT') . '/lib/views/nav_tabs.php');
	include(constant('SAMLAUTH_ROOT') . '/lib/views/sso_general.php');
}

function sso_idp(){
  include(constant('SAMLAUTH_ROOT') . '/lib/views/nav_tabs.php');
	include(constant('SAMLAUTH_ROOT') . '/lib/views/sso_idp.php');
}

function sso_sp()
{  
  include(constant('SAMLAUTH_ROOT') . '/lib/views/nav_tabs.php');
	include(constant('SAMLAUTH_ROOT') . '/lib/views/sso_sp.php');	
}

function sso_help(){
  include(constant('SAMLAUTH_ROOT') . '/lib/views/nav_tabs.php');
	include(constant('SAMLAUTH_ROOT') . '/lib/views/sso_help.php');
}
// end of file 
