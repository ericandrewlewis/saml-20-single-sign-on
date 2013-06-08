<?php
  // Setup Default Options Array
  global $saml_opts;
  
  if (isset($_POST['submit']) ) 
  {    
    
      if( isset($_POST['auto_cert']) )
      {
        $pk = openssl_pkey_new(array('private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA));
    
        global $current_user;
        get_currentuserinfo();
        
        $dn = array(
        "countryName" => "US",
        "organizationName" => get_bloginfo('name'),
        "commonName" => get_bloginfo('name') . " SAML Signing Certificate",
        "emailAddress" => $current_user->user_email
        );
        
        $csr = openssl_csr_new($dn,$pk); 
        $crt = openssl_csr_sign($csr,null,$pk,1825);
        
        $keyfile = null; 
        $certfile = null;
        
        openssl_pkey_export($pk,$keyfile);
        openssl_x509_export($crt,$certfile);
        
        
        $upload_dir = constant('SAMLAUTH_CONF') . '/certs/' . get_current_blog_id();
        
        if(! is_dir($upload_dir))
        {
            mkdir($upload_dir, 0775);
        }
                
        $cert_uploaded = ( file_put_contents($upload_dir . '/' . get_current_blog_id() . '.cer', $certfile) ) ? true : false ;
        $key_uploaded = ( file_put_contents($upload_dir . '/' . get_current_blog_id() . '.key', $keyfile) ) ? true : false ;
        
      }
      elseif( ( isset($_FILES['certificate']) && isset($_FILES['privatekey']) ) && ( $_FILES['certificate']['error'] == 0 && $_FILES['privatekey']['error'] == 0 ) )
        {
            $cert = file_get_contents($_FILES['certificate']['tmp_name']);
            $key = file_get_contents($_FILES['privatekey']['tmp_name']);
            if(openssl_x509_check_private_key($cert,$key))
            {
                $upload_dir = constant('SAMLAUTH_CONF') . '/certs/' . get_current_blog_id();
                if(! is_dir($upload_dir))
                {
                    mkdir($upload_dir, 0775);
                }
                $cert_uploaded = ( file_put_contents($upload_dir . '/' . get_current_blog_id() . '.cer', $cert) ) ? true : false ;
                $key_uploaded = ( file_put_contents($upload_dir . '/' . get_current_blog_id() . '.key', $key) ) ? true : false ;
            }
            else
            {
                echo '<div class="error below-h2"><p>The certificate and private key you provided do not correspond to one another. They were not uploaded.</p></div>'."\n";
            }
        }
        if(get_option('saml_authentication_options'))
        $saml_opts = get_option('saml_authentication_options');

        // Options Array Update
        $saml_opts['idp'] = $_POST['idp'];
        $saml_opts['nameidpolicy'] = $_POST['nameidpolicy'];
        $saml_opts['username_attribute'] = $_POST['username_attribute'];
        $saml_opts['firstname_attribute'] = $_POST['firstname_attribute'];
        $saml_opts['lastname_attribute'] = $_POST['lastname_attribute'];
        $saml_opts['email_attribute'] = $_POST['email_attribute'];
        $saml_opts['groups_attribute'] = $_POST['groups_attribute'];
        $saml_opts['admin_group'] = $_POST['admin_group'];
        $saml_opts['editor_group'] = $_POST['editor_group'];
        $saml_opts['author_group'] = $_POST['author_group'];
        $saml_opts['contributor_group'] = $_POST['contributor_group'];
        $saml_opts['subscriber_group'] = $_POST['subscriber_group'];
        $saml_opts['allow_unlisted_users'] = ($_POST['allow_unlisted_users'] == 'allow') ? true : false;

        update_option('saml_authentication_options', $saml_opts);
  }
  
  // Get Options
  if(get_option('saml_authentication_options'))
  $saml_opts = get_option('saml_authentication_options');

  $status = get_saml_status();

  include(constant('SAMLAUTH_ROOT') . '/lib/views/nav_tabs.php');
	include(constant('SAMLAUTH_ROOT') . '/lib/views/sso_sp.php');

?>