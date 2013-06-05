<?php
  // Setup Default Options Array
  global $saml_opts;
  
  if (isset($_POST['submit']) ) 
  { 
    if(get_option('saml_authentication_options'))
    		$saml_opts = get_option('saml_authentication_options');
    		
    $saml_opts['enabled'] = ($_POST['enabled'] == 'enabled') ? true : false;
    
    update_option('saml_authentication_options', $saml_opts);
  }
  
  if(get_option('saml_authentication_options'))
    		$saml_opts = get_option('saml_authentication_options');

?>

<div class="wrap">
<p><em>Note:</em> Once you enable SAML authentication, WordPress authentication will happen through the Single Sign-On plugin, even if you misconfigure it. To avoid being locked out of WordPress, use a second browser to check your settings before you end this session as Administrator. If you get an error in the other browser, correct your settings here. If you can not resolve the issue, disable this plug-in.</p>

<form method="post" action="<?php echo $_SERVER['PHP_SELF'] . '?page=' . basename(__FILE__); ?>&updated=true">
<table class="form-table">
	<tr valign="top">
    <th scope="row"><label for="enabled">Enable SAML authentication</label></th> 
    <?php
			$checked = ($saml_opts['enabled']) ? ' checked="checked"' : '';
		?><td><input type="checkbox" name="enabled" id="enabled" value="enabled" <?php echo $checked;?> />
    </td>
  </tr>
  <tr>
    <td><input type="submit" name="submit" class="button button-primary" value="Update Options" /></td>
  </tr>
</table>
</form>

<h3>Service Provider Info</h3>
<p>You will need to supply your identity provider with this information. If you want your users to be able to log in directly from WordPress (as opposed to logging in from a separate SSO portal), then you will also need to supply your IdP with the <strong>signing certificate</strong> used above.</p>
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
</div>