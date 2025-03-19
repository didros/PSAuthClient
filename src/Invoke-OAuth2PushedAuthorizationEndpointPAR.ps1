function Invoke-OAuth2PushedAuthorizationEndpoint { 
    <#
    .SYNOPSIS
    Interact with a OAuth2 Authorization endpoint.

    .DESCRIPTION
    Uses WebView2 (embedded browser based on Microsoft Edge) to request authorization, this ensures support for modern web pages and capabilities like SSO, Windows Hello, FIDO key login, etc

    OIDC and OAUTH2 Grants such as Authorization Code Flow with PKCE, Implicit Flow (including form_post) and Hybrid Flows are supported

    .PARAMETER uri
    Authorization endpoint URL.

    .PARAMETER client_id
    The identifier of the client at the authorization server.

    .PARAMETER redirect_uri
    The client callback URI for the authorization response.

    .PARAMETER response_type
    Tells the authorization server which grant to execute. Default is code.

    .PARAMETER scope
    One or more space-separated strings indicating which permissions the application is requesting. 

    .PARAMETER usePkce
    Proof Key for Code Exchange (PKCE) improves security for public clients by preventing and authorization code attacks. Default is $true.

    .PARAMETER response_mode
    OPTIONAL Informs the Authorization Server of the mechanism to be used for returning Authorization Response. Determined by response_type, if not specified.

    .PARAMETER customParameters
    Hashtable with custom parameters added to the request uri (e.g. domain_hint, prompt, etc.) both the key and value will be url encoded. Provided with state, nonce or PKCE keys these values are used in the request (otherwise values are generated accordingly).

    .PARAMETER userAgent
    OPTIONAL Custom User-Agent string to be used in the WebView2 browser.

    .EXAMPLE
    PS> Invoke-OAuth2AuthorizationEndpoint -uri "https://acc.spotify.com/authorize" -client_id "2svXwWbFXj" -scope "user-read-currently-playing" -redirect_uri "http://localhost"
    code_verifier                  xNTKRgsEy_u2Y.PQZTmUbccYd~gp7-5v4HxS7HVKSD2fE.uW_yu77HuA-_sOQ...
    redirect_uri                   https://localhost
    client_id                      2svXwWbFXj
    code                           AQDTWHSP6e3Hx5cuJh_85r_3m-s5IINEcQZzjAZKdV4DP_QRqSHJzK_iNB_hN...

    A request for user authorization is sent to the /authorize endpoint along with a code_challenge, code_challenge_method and state param. 
    If successful, the authorization server will redirect back to the redirect_uri with a code which can be exchanged for an access token.
    
    .EXAMPLE
    PS> Invoke-OAuth2AuthorizationEndpoint -uri "https://example.org/oauth2/authorize" -client_id "0325" -redirect_uri "http://localhost" -scope "user.read" -response_type "token" -usePkce:$false -customParameters @{ login = "none" }
    expires_in                     4146
    expiry_datetime                01.02.2024 10:56:06
    scope                          User.Read profile openid email
    session_state                  5c044a21-543e-4cbc-a94r-d411ddec5a87
    access_token                   eyJ0eXAiQiJKV1QiLCJub25jZSI6InAxYTlHksH6bktYdjhud3VwMklEOGtUM...
    token_type                     Bearer

    Implicit Grant, will return a access_token if successful.
    #>
    [Alias('Invoke-PushedAuthorizationEndpoint','par')]
    [OutputType([hashtable])]
    [cmdletbinding()]
    param(
        [parameter(Position = 0, Mandatory = $true)]
        [string]$uri,

        [parameter( Mandatory = $true)]
        [string]$client_id,

        [parameter( Mandatory = $false)]
        [string]$redirect_uri,
        
        [parameter( Mandatory = $false)]
        [validatePattern("(code)?(id_token)?(token)?(none)?")]
        [string]$response_type = "code",

        [parameter( Mandatory = $false)]
        [string]$scope,

        [parameter( Mandatory = $false)]
        [bool]$usePkce = $true,

        [parameter( Mandatory = $false)]
        [ValidateSet("query","fragment","form_post")]
        [string]$response_mode,

        [parameter( Mandatory = $false)]
        [hashtable]$customParameters,

        [parameter( Mandatory = $false)]
        [string]$userAgent
    )

    
    $payload = @{}
    $payload.headers = @{ 'Content-Type' = 'application/x-www-form-urlencoded' }
    $payload.method  = 'Post'
    $payload.uri     =  $uri

    # Determine which protocol is being used.
    if ( $response_type -eq "token" -or ($response_type -match "^code$" -and $scope -notmatch "openid" ) ) { $protocol = "OAUTH"; $nonce = $null }
    else { $protocol = "OIDC"
        # ensure scope contains openid for oidc flows
        if ( $scope -notmatch "openid" ) { Write-Warning "Invoke-OAuth2AuthorizationRequest: Added openid scope to request (OpenID requirement)."; $scope += " openid" }
        # ensure nonce is present for id_token validation
        if ( $customParameters -and $customParameters.Keys -match "^nonce$" ) { [string]$nonce = $customParameters["nonce"] }
        else { [string]$nonce = Get-RandomString -Length ( (32..64) | get-random ) }
    }

    # state for CSRF protection (optional, but recommended)
    if ( $customParameters -and $customParameters.Keys -match "^state$" ) { [string]$state = $customParameters["state"] }
    else { [string]$state = Get-RandomString -Length ( (16..21) | get-random ) }
    
    # building the request 
    $requestBody = @{}
    $requestBody.response_type=$response_type
    $requestBody.client_id=$client_id
    $requestBody.state=$state
    if ( $redirect_uri ) { $requestBody.redirect_uri=$redirect_uri } 
    if ( $scope ) { $requestBody.scope=$scope }
    if ( $nonce ) { $requestBody.nonce=$nonce }
    
    # PKCE for code flows
    if ( $response_type -notmatch "code" -and $usePkce ) { write-verbose "Invoke-OAuth2AuthorizationRequest: PKCE is not supported for implicit flows." }
    else { 
        if ( $usePkce ) {
            # pkce provided in custom parameters
            if ( $customParameters -and $customParameters.Keys -match "^code_challenge$" ) {
                $pkce = @{ code_challenge = $customParameters["code_challenge"] }
                if ( $customParameters.Keys -match "^code_challenge_method$" ) { $pkce.code_challenge_method = $customParameters["code_challenge_method"] }
                else { Write-Warning "Invoke-OAuth2AuthorizationRequest: code_challenge_method not specified, defaulting to 'S256'."; $pkce.code_challenge_method = "S256" }
                if ( $customParameters.Keys -match "^code_verifier$" ) { $pkce.code_verifier = $customParameters["code_verifier"] }
            }
            # generate new pkce challenge
            else { $pkce = New-PkceChallenge }
            # add to request uri
            $requestBody.code_challenge=$pkce.code_challenge
            $requestBody.code_challenge_method=$pkce.code_challenge_method
        }
    }

    # Add custom parameters to request uri
    if ( $customParameters ) { 
        foreach ( $key in ($customParameters.Keys | Where-Object { $_ -notmatch "^nonce$|^state$|^code_(challenge(_method)?$|verifier)$" }) ) { 
            $requestBody.$($key)=$customParameters[$key]
        }
    }
    
    Write-Verbose "Invoke-OAuth2AuthorizationRequestPAR:"
    $payload.body = $requestBody
    write-verbose ($payload | ConvertTo-Json -Compress)

    try { $response = Invoke-RestMethod @payload -Verbose:$false }
    catch { throw $_ }

    Write-Verbose $response

    # add expiry datetime
    if ( $response.expires_in ) { $response | Add-Member -NotePropertyName expiry_datetime -TypeName NoteProperty (get-date).AddSeconds($response.expires_in) }

    return $response
}