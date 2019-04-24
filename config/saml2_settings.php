<?php

//This is variable is an example - Just make sure that the urls in the 'idp' config are ok.
$idp_host = env('SAML2_IDP_HOST', 'http://localhost:8000/simplesaml');

return $settings = array(

    /**
     * If 'useRoutes' is set to true, the package defines five new routes:
     *
     *    Method | URI                      | Name
     *    -------|--------------------------|------------------
     *    POST   | {routesPrefix}/acs       | saml_acs
     *    GET    | {routesPrefix}/login     | saml_login
     *    GET    | {routesPrefix}/logout    | saml_logout
     *    GET    | {routesPrefix}/metadata  | saml_metadata
     *    GET    | {routesPrefix}/sls       | saml_sls
     */
    'useRoutes' => true,

    'routesPrefix' => '/saml2',

    /**
     * which middleware group to use for the saml routes
     * Laravel 5.2 will need a group which includes StartSession
     */
    'routesMiddleware' => [],

    /**
     * Indicates how the parameters will be
     * retrieved from the sls request for signature validation
     */
    'retrieveParametersFromServer' => false,

    /**
     * Where to redirect after logout
     */
    'logoutRoute' => '/',

    /**
     * Where to redirect after login if no other option was provided
     */
    'loginRoute' => '/',


    /**
     * Where to redirect after login if no other option was provided
     */
    'errorRoute' => '/',




    /*****
     * One Login Settings
     */



    // If 'strict' is True, then the PHP Toolkit will reject unsigned
    // or unencrypted messages if it expects them signed or encrypted
    // Also will reject the messages if not strictly follow the SAML
    // standard: Destination, NameId, Conditions ... are validated too.
    'strict' => true, //@todo: make this depend on laravel config

    // Enable debug mode (to print errors)
    'debug' => env('APP_DEBUG', false),

    // If 'proxyVars' is True, then the Saml lib will trust proxy headers
    // e.g X-Forwarded-Proto / HTTP_X_FORWARDED_PROTO. This is useful if
    // your application is running behind a load balancer which terminates
    // SSL.
    'proxyVars' => false,

    // Service Provider Data that we are deploying
    'sp' => array(

        // Specifies constraints on the name identifier to be used to
        // represent the requested subject.
        // Take a look on lib/Saml2/Constants.php to see the NameIdFormat supported
        'NameIDFormat' => 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',

        // Usually x509cert and privateKey of the SP are provided by files placed at
        // the certs folder. But we can also provide them with the following parameters
        'x509cert' => env('SAML2_SP_x509',''),
        'privateKey' => env('SAML2_SP_PRIVATEKEY',''),

        // Identifier (URI) of the SP entity.
        // Leave blank to use the 'saml_metadata' route.
        'entityId' => 'http://localhost:8000/saml2/metadata',

        // Specifies info about where and how the <AuthnResponse> message MUST be
        // returned to the requester, in this case our SP.
        'assertionConsumerService' => array(
            // URL Location where the <Response> from the IdP will be returned,
            // using HTTP-POST binding.
            // Leave blank to use the 'saml_acs' route
            'url' => 'http://localhost:8000/saml2/acs',
        ),
        // Specifies info about where and how the <Logout Response> message MUST be
        // returned to the requester, in this case our SP.
        // Remove this part to not include any URL Location in the metadata.
        'singleLogoutService' => array(
            // URL Location where the <Response> from the IdP will be returned,
            // using HTTP-Redirect binding.
            // Leave blank to use the 'saml_sls' route
            'url' => 'http://localhost:8000/saml2/sls',
        ),
    ),

    // Identity Provider Data that we want connect with our SP
    'idp' => array(
        // Identifier of the IdP entity  (must be a URI)
	    'entityId' => 'https://ec2-54-69-83-188.us-west-2.compute.amazonaws.com/simplesaml/saml2/idp/metadata.php',
        // SSO endpoint info of the IdP. (Authentication Request protocol)
        'singleSignOnService' => array(
            // URL Target of the IdP where the SP will send the Authentication Request Message,
            // using HTTP-Redirect binding.
            'url' => 'https://ec2-54-69-83-188.us-west-2.compute.amazonaws.com/simplesaml/saml2/idp/SSOService.php',
        ),
        // SLO endpoint info of the IdP.
        'singleLogoutService' => array(
            // URL Location of the IdP where the SP will send the SLO Request,
            // using HTTP-Redirect binding.
            'url' => 'https://ec2-54-69-83-188.us-west-2.compute.amazonaws.com/simplesaml/saml2/idp/SingleLogoutService.php',
        ),
        // Public x509 certificate of the IdP
	'x509cert' => 'MIIEKzCCAxOgAwIBAgIJAJ2JJlU+OLyRMA0GCSqGSIb3DQEBCwUAMIGrMQswCQYDVQQGEwJVUzENMAsGA1UECAwET2hpbzEPMA0GA1UEBwwGQXRoZW5zMRgwFgYDVQQKDA9JRE0gSW50ZWdyYXRpb24xOTA3BgNVBAMMMGVjMi01NC02OS04My0xODgudXMtd2VzdC0yLmNvbXB1dGUuYW1hem9uYXdzLmNvbTEnMCUGCSqGSIb3DQEJARYYZGF2aWRAaWRtaW50ZWdyYXRpb24uY29tMB4XDTE1MDcyMzAwNTI1N1oXDTI1MDcyMjAwNTI1N1owgasxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIDARPaGlvMQ8wDQYDVQQHDAZBdGhlbnMxGDAWBgNVBAoMD0lETSBJbnRlZ3JhdGlvbjE5MDcGA1UEAwwwZWMyLTU0LTY5LTgzLTE4OC51cy13ZXN0LTIuY29tcHV0ZS5hbWF6b25hd3MuY29tMScwJQYJKoZIhvcNAQkBFhhkYXZpZEBpZG1pbnRlZ3JhdGlvbi5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDLMEcRKoIjfeXM7Ovd4VbF2vuet0EfIAn/Ovqpdw0DBD+3HH/L2ZWX7JnWf/JySkuIn7fyCJNUhLrYXlVxif6zPBBDQqW2nFCLvINxWauWP8hA6mHWijV7eNg4trvrpkOyEZioVcjRzBan2WP+yd3wQYTbOR3LATi97gTWq//EldH5spLLq2eTHAoxHYGDPVJegIt19aE9l4dnGuBcTER4pcHkb3sF3u40lNNPcJRcwfrvw32qX9nKNXdutOR+UyA9e65RJmOuWKQ3yS6KmWB9kkJdY2bFIG9CqRODl4hdPsOl+uqzx/GNxDy6o3B6UGvAw+RtRkZGZzPWx3rR2jHzAgMBAAGjUDBOMB0GA1UdDgQWBBTmd4lNnf7tkkfTvUH7HqqFgIAFpDAfBgNVHSMEGDAWgBTmd4lNnf7tkkfTvUH7HqqFgIAFpDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBYSymVUEeDhQKFJxnHHitReAnN7aoSTav5M8CQI+EgQQ5PwIr0UyD1NZlNVkz1q77r5gA+NkDKcsPQ/WbNTi1qW1gBSejDRouXkP5Zy+Hnj8b1QEXvyRZtMiFF++CW9LVtEN60bAcpaoTr4J7KJLNPUOho/c1ja5rbyuTm8Vrga1jwXmL/EE6zE+9hpnwoZZdCViFdqaSkW4MZl0iSwwWkBuQB9b3gataaRRCN1bLKelJvC6iQMU22Ilsp4snGzAceYr02eoCh/sS8yeiZoJNkq/auBuTWCSu1ilCDvIMAx+pIMvl9I3k9aPvVGF6oebvCS25Wl5vPkvvOIYibHdCW', 
        /*
         *  Instead of use the whole x509cert you can use a fingerprint
         *  (openssl x509 -noout -fingerprint -in "idp.crt" to generate it)
         */
        // 'certFingerprint' => '',
    ),



    /***
     *
     *  OneLogin advanced settings
     *
     *
     */
    // Security settings
    'security' => array(

        /** signatures and encryptions offered */

        // Indicates that the nameID of the <samlp:logoutRequest> sent by this SP
        // will be encrypted.
        'nameIdEncrypted' => false,

        // Indicates whether the <samlp:AuthnRequest> messages sent by this SP
        // will be signed.              [The Metadata of the SP will offer this info]
        'authnRequestsSigned' => false,

        // Indicates whether the <samlp:logoutRequest> messages sent by this SP
        // will be signed.
        'logoutRequestSigned' => false,

        // Indicates whether the <samlp:logoutResponse> messages sent by this SP
        // will be signed.
        'logoutResponseSigned' => false,

        /* Sign the Metadata
         False || True (use sp certs) || array (
                                                    keyFileName => 'metadata.key',
                                                    certFileName => 'metadata.crt'
                                                )
        */
        'signMetadata' => false,


        /** signatures and encryptions required **/

        // Indicates a requirement for the <samlp:Response>, <samlp:LogoutRequest> and
        // <samlp:LogoutResponse> elements received by this SP to be signed.
        'wantMessagesSigned' => false,

        // Indicates a requirement for the <saml:Assertion> elements received by
        // this SP to be signed.        [The Metadata of the SP will offer this info]
        'wantAssertionsSigned' => false,

        // Indicates a requirement for the NameID received by
        // this SP to be encrypted.
        'wantNameIdEncrypted' => false,

        // Authentication context.
        // Set to false and no AuthContext will be sent in the AuthNRequest,
        // Set true or don't present thi parameter and you will get an AuthContext 'exact' 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
        // Set an array with the possible auth context values: array ('urn:oasis:names:tc:SAML:2.0:ac:classes:Password', 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509'),
        'requestedAuthnContext' => true,
    ),

    // Contact information template, it is recommended to suply a technical and support contacts
    'contactPerson' => array(
        'technical' => array(
            'givenName' => 'name',
            'emailAddress' => 'no@reply.com'
        ),
        'support' => array(
            'givenName' => 'Support',
            'emailAddress' => 'no@reply.com'
        ),
    ),

    // Organization information template, the info in en_US lang is recomended, add more if required
    'organization' => array(
        'en-US' => array(
            'name' => 'Name',
            'displayname' => 'Display Name',
            'url' => 'http://url'
        ),
    ),

/* Interoperable SAML 2.0 Web Browser SSO Profile [saml2int]   http://saml2int.org/profile/current

   'authnRequestsSigned' => false,    // SP SHOULD NOT sign the <samlp:AuthnRequest>,
                                      // MUST NOT assume that the IdP validates the sign
   'wantAssertionsSigned' => true,
   'wantAssertionsEncrypted' => true, // MUST be enabled if SSL/HTTPs is disabled
   'wantNameIdEncrypted' => false,
*/

);
