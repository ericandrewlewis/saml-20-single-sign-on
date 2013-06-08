<?php
  // Setup Default Options Array
  global $saml_opts;
  $status = get_saml_status();
  
  if (isset($_POST['submit']) ) 
  { 
    if(get_option('saml_authentication_options'))
    		$saml_opts = get_option('saml_authentication_options');
    		
    if(isset($_POST['enabled']) && $_POST['enabled'] == 'enabled')
    {
      if($status->num_errors === 0)
      {
        $saml_opts['enabled'] = true;
      }
      else
      {
        $saml_opts['enabled'] = false;
        echo '<div class="error settings-error"><p>There are still errors in your SAML configuration (see the status table below). You cannot enable SAML authentication until all errors are resolved.</p></div>'."\n";
        echo '<script type="text/javascript">jQuery(\'.updated.settings-error\').remove();</script>';
      }
    }
    else
    {
      $saml_opts['enabled'] = false;
    }
    update_option('saml_authentication_options', $saml_opts);
  }
  
  if(get_option('saml_authentication_options'))
  {
		$saml_opts = get_option('saml_authentication_options');
	}

  include(constant('SAMLAUTH_ROOT') . '/lib/views/nav_tabs.php');
	include(constant('SAMLAUTH_ROOT') . '/lib/views/sso_general.php');

?>