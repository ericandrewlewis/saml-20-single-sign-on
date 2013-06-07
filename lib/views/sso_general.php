<?php
  // Setup Default Options Array
  global $saml_opts;
  
  if (isset($_POST['submit']) ) 
  { 
    if(get_option('saml_authentication_options'))
    		$saml_opts = get_option('saml_authentication_options');
    		
    $saml_opts['enabled'] = (isset($_POST['enabled']) && $_POST['enabled'] == 'enabled') ? true : false;
    
    update_option('saml_authentication_options', $saml_opts);
  }
  
  if(get_option('saml_authentication_options'))
    		$saml_opts = get_option('saml_authentication_options');

?>

<div class="wrap">


<h3>Status</h3>
<?php
  $status = array(
    'idp_entityid' => array(
        'error'   => 'You have not changed your IdP&rsquo;s Entity ID from the default value. You should update it to a real value.',
        'warning' => 'The Entity ID you provided may not be a accessible (perhaps a bad URL). You should check that it is correct.',
        'ok'      => 'You have provided an Entity ID for your IdP.',
      ),
      'idp_sso' => array(
        'error'   => 'You have not changed your IdP&rsquo;s Single Sign-On URL from the default value. You should update it to a real value.',
        'warning' => 'You have not provided a Single Sign-On URL for your IdP. Users will have to log in using the <a href="?page=sso_help.php#idp-first-flow">IdP-first flow</a>.',
        'ok'      => 'You have provided a Single Sign-On URL for your IdP.',
      ), 
      'idp_slo' => array(
        'error'   => 'You have not changed your IdP&rsquo;s Single Logout URL from the default value. You should update it to a real value.',
        'warning' => 'You have not provided a Single Logout URL for your IdP. Users will not be logged out of the IdP when logging out of your site.',
        'ok'      => 'You have provided a Single Logout URL for your IdP.',
      ),  
      'idp_fingerprint' => array(
        'error'   => 'You have not provided a Certificate Fingerprint for your IdP',
        'warning' => '',
        'ok'      => 'You have provided a Certificate Fingerprint for your IdP.',
      ), 
      'sp_certificate' => array(
        'error'   => '',
        'warning' => 'You have not provided a Certificate or Private Key for this site. Users may not be able to log in using the SP-first flow.',
        'ok'      => 'You have provided a Certificate and Private Key for this site.',
      ), 
      'sp_permissions' => array(
        'error'   => 'You have not specified any permissions for SSO users. All SSO users will either be subscribers, or fail to log in.',
        'warning' => 'You have specified some permissions, but no SSO users will be administrators. This could cause you to lose access to your site.',
        'ok'      => 'You have specified permissions for this site.',
      )
  );
  
  $status_html = array(
    'error'   => array(
      '<tr class="red"><td><i class="icon-remove icon-large"></i></td><td>',
      '</td></tr>'
    ),
    'warning' => array(
      '<tr class="yellow"><td><i class="icon-warning-sign icon-large"></i></td><td>',
      '</td></tr>'
    ),
    'ok'      => array(
      '<tr class="green"><td><i class="icon-ok icon-large"></i></td><td>',
      '</td></tr>'
    )
  );
  
  $idp_ini = parse_ini_file(constant('SAMLAUTH_CONF') . '/config/saml20-idp-remote.ini',true);
  $opt = get_option('saml_authentication_options');
  
  echo '<table class="saml_status">'."\n";
  
  if (is_array($idp_ini))
  {  
    foreach($idp_ini as $key => $val)
    {
      if( $key != 'https://your-idp.net')
      {
        echo $status_html['ok'][0] . $status['idp_entityid']['ok'] . $status_html['ok'][1]; 
      }
      else
      {
        echo $status_html['error'][0] . $status['idp_entityid']['error'] . $status_html['ok'][1];
      }
      
      if( $val['SingleSignOnService'] == 'https://your-idp.net/SSOService' )
      {
        echo $status_html['error'][0] . $status['idp_sso']['error'] . $status_html['error'][1];
      }
      elseif( trim( $val['SingleSignOnService'] ) != '')
      {
        echo $status_html['ok'][0] . $status['idp_sso']['ok'] . $status_html['ok'][1];
      }
      else
      {
        echo $status_html['warning'][0] . $status['idp_sso']['warning'] . $status_html['warning'][1];
      }
      
      if( $val['SingleLogoutService'] == 'https://your-idp.net/SingleLogoutService' )
      {
        echo $status_html['error'][0] . $status['idp_slo']['error'] . $status_html['error'][1];
      }
      elseif( trim( $val['SingleLogoutService'] ) != '')
      {
        echo $status_html['ok'][0] . $status['idp_slo']['ok'] . $status_html['ok'][1];
      }
      else
      {
        echo $status_html['warning'][0] . $status['idp_slo']['warning'] . $status_html['warning'][1];
      }
      
      if( $val['certFingerprint'] != '0000000000000000000000000000000000000000' && $val['certFingerprint'] != '')
      {
        echo $status_html['ok'][0] . $status['idp_fingerprint']['ok'] . $status_html['ok'][1];
      }
      else
      {
        echo $status_html['error'][0] . $status['idp_fingerprint']['error'] . $status_html['ok'][1];
      }
    }
  }
  
  if(file_exists(constant('SAMLAUTH_CONF') . '/certs/' . get_current_blog_id() . '/' . get_current_blog_id() . '.cer') && file_exists(constant('SAMLAUTH_CONF') . '/certs/' . get_current_blog_id() . '/' . get_current_blog_id() . '.key'))
  {
    echo $status_html['ok'][0] . $status['sp_certificate']['ok'] . $status_html['ok'][1];
  }
  else
  {
    echo $status_html['warning'][0] . $status['sp_certificate']['warning'] . $status_html['warning'][1];
  }
  
  if( trim($opt['admin_group']) != '' )
  {
    echo $status_html['ok'][0] . $status['sp_permissions']['ok'] . $status_html['ok'][1];
  }
  elseif(trim($opt['admin_group']) == '' && (trim($opt['editor_group']) != '' || trim($opt['author_group']) != '' || trim($opt['contributor_group']) != '' || trim($opt['subscriber_group']) != '') )
  {
    echo $status_html['warning'][0] . $status['sp_permissions']['warning'] . $status_html['warning'][1];
  }
  elseif( trim($opt['admin_group']) == '' && trim($opt['editor_group']) == '' && trim($opt['author_group']) == '' && trim($opt['contributor_group']) == '' && trim($opt['subscriber_group']) == '' )
  {
    echo $status_html['error'][0] . $status['sp_permissions']['error'] . $status_html['error'][1];
  }
  
  echo '</table>'."\n";

?>
<br/>
<div class="option-separator"></div>

<h3>Your SAML Info</h3>
<p>You will need to supply your identity provider with this information. If you want your users to be able to log in directly from WordPress (as opposed to logging in from a separate SSO portal), then you will also need to supply your IdP with the <strong>signing certificate</strong> used on the <a href="?page=sso_sp.php">Service Provider tab</a>.</p>
  <?php
	  $c = curl_init(constant('SAMLAUTH_URL') . '/saml/www/module.php/saml/sp/metadata.php/' . get_current_blog_id());
		curl_setopt($c, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
		$o = curl_exec($c);
		
  	preg_match('/(entityID="(?P<entityID>.*)")/',$o,$entityID);
		preg_match('/(<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="(?P<Logout>.*)")/',$o,$Logout);
		preg_match('/(<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="(?P<Consumer>.*)" index)/',$o,$Consumer);
		
		$metadata['entityID'] = $entityID['entityID'];
		$metadata['Logout'] = $Logout['Logout'];
		$metadata['Consumer'] = $Consumer['Consumer'];
	?>
  <p>
    <strong>Your Entity ID:</strong><br/>
    <pre class="metadata-box">
    <?php echo $metadata['entityID'];?>
    </pre>
  </p>
  <p>
    <strong>Your Single Logout URL:</strong><br/>
    <pre class="metadata-box">
    <?php echo $metadata['Logout'];?>
    </pre>
  </p>
  <p>
    <strong>Your SAML Assertion Consumer URL:</strong><br/>
    <pre class="metadata-box">
    <?php echo $metadata['Consumer'];?>
    </pre>
  </p>
  <br/>
  <div class="option-separator"></div>

<form method="post" action="<?php echo $_SERVER['PHP_SELF'] . '?page=' . basename(__FILE__); ?>&updated=true">
<table class="form-table">
	<tr valign="top">
    <th scope="row"><label for="enabled"><strong>Enable SAML authentication</strong></label></th> 
    <?php
			$checked = ($saml_opts['enabled']) ? ' checked="checked"' : '';
		?><td><input type="checkbox" name="enabled" id="enabled" value="enabled" <?php echo $checked;?> />
    </td>
    </tr>
    <tr>
    <td colspan="2">
      <p style="width: 480px;"><i class="blue icon-lightbulb icon-3x" style="float:left;margin-right: 0.25em;"></i> <strong>Tip:</strong> You can use a different browser (or a Google Chrome Incognito window) to test SAML authentication, while leaving this window open. If SAML logins don't work right away, you can use this window to troubleshoot.</p>
    </td>
  </tr>
  <tr>
    <td><input type="submit" name="submit" class="button button-primary" value="Update Options" /></td>
  </tr>
</table>
</form>
</div>