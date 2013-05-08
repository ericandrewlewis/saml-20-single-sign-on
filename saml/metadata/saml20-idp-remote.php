<?php

$ini = parse_ini_file('/opt/www/wordpress/wp-content/uploads/saml-20-single-sign-on/etc/config/saml20-idp-remote.ini',true);
foreach($ini as $key => $array)
{
	
	$metadata[$key] = array(
					'name' => array(
									'en' => $array['name']
					),
					'SingleSignOnService'  => $array['SingleSignOnService'],
					'SingleLogoutService'  => $array['SingleLogoutService'],
					'certFingerprint'      => $array['certFingerprint']
	);

}

