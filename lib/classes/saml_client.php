<?php
class SAML_Client
{
  private $saml;
  private $opt;
  private $secretsauce;
  
  function __construct()
  {
    $this->settings = new SAML_Settings();
    
    require_once(constant('SAMLAUTH_ROOT') . '/saml/lib/_autoload.php');
		if( $this->settings->get_enabled() )
		{
			$this->saml = new SimpleSAML_Auth_Simple((string)get_current_blog_id());
			
			add_action('wp_authenticate',array($this,'authenticate'));
	    add_action('wp_logout',array($this,'logout'));
		}
    
    // Hash to generate password for SAML users.
    // This is never actually used by the user, but we need to know what it is, and it needs to be consistent
    
    // WARNING: If the WP AUTH_KEY is changed, all SAML users will be unable to login! In cases where this is
    //   actually desired, such as an intrusion, you must delete SAML users or manually set their passwords.
    //   it's messy, so be careful!

    $this->secretsauce = constant('AUTH_KEY');
  }
  
  public function authenticate()
  {
    if( isset($_GET['loggedout']) && $_GET['loggedout'] == 'true' )
    {
      header('Location: ' . get_option('siteurl'));
      exit();
    }
    else
    {
      $this->saml->requireAuth( array('ReturnTo' => get_admin_url() ) );
      $attrs = $this->saml->getAttributes();
      $username = $attrs[$this->settings->get_attribute('username')][0];
      if(get_user_by('login',$username))
      {
        $this->simulate_signon($username);
      }
      else
      {
        $this->new_user($attrs);
      }
    }
  }
  
  public function logout()
  { 
    //header('Location: ' . $this->saml->getLogoutURL( get_option('siteurl') ));
    $this->saml->logout( get_option('siteurl') );
    // exit();
  }
  
  private function new_user($attrs)
  {
    $login = $attrs[$this->settings->get_attribute('username')][0];
    $email = $attrs[$this->settings->get_attribute('email')][0];
    $first_name = $attrs[$this->settings->get_attribute('firstname')][0];
    $last_name = $attrs[$this->settings->get_attribute('lastname')][0];
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
    if( in_array($this->settings->get_group('admin'),$attrs[$this->settings->get_attribute('groups')]) )
    {
      $role = 'administrator';
    }
    elseif( in_array($this->settings->get_group('editor'),$attrs[$this->settings->get_attribute('groups')]) )
    {
      $role = 'editor';
    }
    elseif( in_array($this->settings->get_group('author'),$attrs[$this->settings->get_attribute('groups')]) )
    {
      $role = 'author';
    }
    elseif( in_array($this->settings->get_group('contributor'),$attrs[$this->settings->get_attribute('groups')]) )
    {
      $role = 'contributor';
    }
    elseif( in_array($this->settings->get_group('subscriber'),$attrs[$this->settings->get_attribute('groups')]) )
    {
      $role = 'subscriber';
    }
    elseif( $this->settings->get_allow_unlisted_users() )
    {
      $role = 'subscriber';
    }
    else
    {
      $role = FALSE;
    }
    
    $user = get_user_by('login',$attrs[$this->settings->get_attribute('username')]);
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
  
  public function show_password_fields($show_password_fields) {
    return false;
  }
  
  public function disable_function() {
    die('Disabled');
  }
  
} // End of Class SamlAuth