<?php
    /*  IdP Options
     *
     *  This function reads the IdP configuration file used by SimpleSAMLPHP and parses the configured IdPs.
     *  It then presents the user with an interface to modify the IdP details.
     *
     */
    
    if ( isset($_POST['fetch_metadata']) )
    {
      $c = curl_init($_POST['metadata_url']);
      curl_setopt($c, CURLOPT_RETURNTRANSFER, true);
      curl_setopt($c, CURLOPT_SSL_VERIFYPEER, false);
      curl_setopt($c, CURLOPT_HEADER, false);
      
      $m = curl_exec($c);
      $x = xml_parser_create();
      
      $d = array();
      $i = array();
      
      if( xml_parse_into_struct($x,$m,$d,$i) )
      {
       // echo '<pre>' . print_r($d, true) . '</pre>';
        $idp_data = array('idp_name' => 'My SSO Provider');
        
        if(array_key_exists('ENTITYDESCRIPTOR',$i))
        {
          $idp_data['idp_identifier'] = $d[$i['ENTITYDESCRIPTOR'][0]]['attributes']['ENTITYID'];
        }
        elseif( array_key_exists('MD:ENTITYDESCRIPTOR',$i) )
        {
          $idp_data['idp_identifier'] = $d[$i['MD:ENTITYDESCRIPTOR'][0]]['attributes']['ENTITYID'];
        }
        else
        {
          $idp_data['idp_identifier'] = '';
        }
        
        if( array_key_exists('SINGLESIGNONSERVICE',$i) )
        {
          $idp_data['idp_signon'] = $d[$i['SINGLESIGNONSERVICE'][0]]['attributes']['LOCATION'];
        }
        elseif( array_key_exists('MD:SINGLESIGNONSERVICE',$i) )
        {
          $idp_data['idp_signon'] = $d[$i['MD:SINGLESIGNONSERVICE'][0]]['attributes']['LOCATION'];
        }
        else
        {
          $idp_data['idp_signon'] = '';
        }
        
        if( array_key_exists('SINGLELOGOUTSERVICE',$i) )
        {
          $idp_data['idp_logout'] = $d[$i['SINGLELOGOUTSERVICE'][0]]['attributes']['LOCATION'];
        }
        elseif( array_key_exists('MD:SINGLELOGOUTSERVICE',$i) )
        {
          $idp_data['idp_logout'] = $d[$i['MD:SINGLELOGOUTSERVICE'][0]]['attributes']['LOCATION'];
        }
        else
        {
          $idp_data['idp_logout'] = '';
        }
        
        if ( array_key_exists('DS:X509CERTIFICATE',$i) )
        {
          $idp_data['idp_fingerprint'] = sha1( base64_decode( $d[$i['DS:X509CERTIFICATE'][0]]['value'] ) );
        }
        elseif ( array_key_exists('X509CERTIFICATE',$i) )
        {
          $idp_data['idp_fingerprint'] = sha1( base64_decode( $d[$i['X509CERTIFICATE'][0]]['value'] ) );
        }
        else
        {
          $idp_data['idp_fingerprint'] = '0000000000000000000000000000000000000000';
        }
        
        $contents =  '[' . $idp_data['idp_identifier'] . ']'."\n";
        $contents .= '  name = "' . $idp_data['idp_name'] . '"'."\n";
        $contents .= '  SingleSignOnService = "' . $idp_data['idp_signon'] . '"'."\n";
        $contents .= '  SingleLogoutService = "' . $idp_data['idp_logout'] . '"'."\n";
        $contents .= '  certFingerprint = "' . str_replace(':','',$idp_data['idp_fingerprint']) . '"'."\n";
        
        $save_status = file_put_contents( constant('SAMLAUTH_CONF') . '/config/saml20-idp-remote.ini', $contents );
        
      }
    }
     
    elseif (isset($_POST['submit']) ) 
    {
        $old_ini = parse_ini_file(constant('SAMLAUTH_CONF') . '/config/saml20-idp-remote.ini',true);
        
        foreach($old_ini as $key => $val)
        {
            if($key != $_POST['idp_identifier'])
            {
                if(get_option('saml_authentication_options'))
                $saml_opts = get_option('saml_authentication_options');
                // Options Array Update
                $saml_opts['idp'] = $_POST['idp_identifier'];
                update_option('saml_authentication_options', $saml_opts);
            }
        }
        
        $contents =  '[' . $_POST['idp_identifier'] . ']'."\n";
        $contents .= '  name = "' . $_POST['idp_name'] . '"'."\n";
        $contents .= '  SingleSignOnService = "' . $_POST['idp_signon'] . '"'."\n";
        $contents .= '  SingleLogoutService = "' . $_POST['idp_logout'] . '"'."\n";
        $contents .= '  certFingerprint = "' . str_replace(':','',$_POST['idp_fingerprint']) . '"'."\n";
        
        $save_status = file_put_contents( constant('SAMLAUTH_CONF') . '/config/saml20-idp-remote.ini', $contents ); 
    }
    
      $metadata = array(); // the variable used in the idp file.
      require( constant('SAMLAUTH_ROOT') . '/saml/metadata/saml20-idp-remote.php' );
    ?>
<div class="wrap">
    <h2>SAML Identity Provider Settings</h2>
    <p><strong>Note:</strong> A valid Identity Provider (IdP) must be defined before <?php if( is_multisite()){ echo 'any sites in the network';} else{ echo 'the site';}?> can use Single-Sign On.<?php if( is_multisite()){ echo ' These settings affect all sites in your network.';}?></p>
  <?php 
      // Check some config setttings.
        
        $etc_dir =  constant('SAMLAUTH_CONF');
        $etc_writable = is_writable($etc_dir);
        $idp_ini_present =  file_exists(constant('SAMLAUTH_CONF') . '/config/saml20-idp-remote.ini');
    
        if( !$etc_writable )
        {
            echo '<div class="error below-h2"><p>I\'m not able to write to the folder <code>' . $etc_dir . '</code> which means you won\'t be able to change any settings! Please ensure that the web server has permission to make changes to this folder.</p></div>'."\n";
        }
        
        if( isset($save_status) && $save_status === FALSE )
        {
            echo '<div class="error below-h2"><p>Your changes couldn&rsquo;t be saved. Is the file writable by the server?</p></div>'."\n";
        }
    ?>
  <form method="post" action="<?php echo $_SERVER['PHP_SELF'] . '?page=' . basename(__FILE__); ?>&updated=true">
    <h3>Autofill using Metadata</h3>
    <label for="metadata_url">URL to IdP Metadata </label><input type="text" name="metadata_url" size="40" />
    <input type="submit" name="fetch_metadata" class="button" value="Fetch Metadata"/>
  </form><br/>
  
  <div class="option-separator"><span class="caption">OR</span></div>
    
  <form method="post" action="<?php echo $_SERVER['PHP_SELF'] . '?page=' . basename(__FILE__); ?>&updated=true">
  
    <h3>Enter IdP Info Manually</h3>
    <fieldset class="options">
    
    
    
    <table class="form-table">
        <?php
            foreach($metadata as $key => $idp)
            {
?>
<tr valign="top">
  <th scope="row"><label for="idp_name">IdP name</label></th> 
  <td><input type="text" name="idp_name" id="sp_auth_inp" value="<?php echo $idp['name']['en']; ?>" size="40" />
  <span class="setting-description">The name that will appear when setting up a service provider.</span> 
  </td>
</tr>
<tr valign="top">
  <th scope="row"><label for="idp_identifier">URL Identifier</label></th> 
  <td><input type="text" name="idp_identifier" id="idp_identifier" value="<?php echo $key; ?>" size="40" />
  <span class="setting-description">The URL that identifies this particular IdP.</span> 
  </td>
</tr>
<tr valign="top">
  <th scope="row"><label for="idp_signon">Single Sign-On URL</label></th> 
  <td><input type="text" name="idp_signon" id="idp_signon" value="<?php echo $idp['SingleSignOnService']; ?>" size="40" />
  <span class="setting-description">Tthe URL where sign-on assertions are sent.</span> 
  </td>
</tr>
<tr valign="top">
  <th scope="row"><label for="idp_logout">Single Logout URL</label></th> 
  <td><input type="text" name="idp_logout" id="idp_logout" value="<?php echo $idp['SingleLogoutService']; ?>" size="40" />
  <span class="setting-description">The URL where logout assertions are sent.</span> 
  </td>
</tr>
<tr valign="top">
  <th scope="row"><label for="idp_fingerprint">Certificate Fingerprint</label></th> 
  <td><input type="text" name="idp_fingerprint" id="idp_fingerprint" value="<?php echo implode(":",str_split($idp['certFingerprint'],2)); ?>" size="40" style="font-family: monospace;"/>
  <span class="setting-description">The fingerprint of the certificate that the IdP uses to sign assertions.</span> 
  </td>
</tr>
<?php   
            }
            ?>
    </table>
    </fieldset>
    <div class="submit">
      <input type="submit" name="submit" class="button button-primary" value="Update Options" />
    </div>
  </form>
  
 
</div>