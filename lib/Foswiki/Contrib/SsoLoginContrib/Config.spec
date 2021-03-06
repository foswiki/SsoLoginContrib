# ---+ Extensions
# ---++ SSO Login Contrib
# This is the configuration of the <b>SsoLoginContrib</b>.
# <p />
# To use SSO (single sign-on) for authentication you need to:
# <br />- set the {LoginManager} to <b>Foswiki::LoginManager::SsoLogin</b>,
# <br />- remove the <b>@</b> sign from {LoginNameFilterIn},
# <br />- set {Register}{AllowLoginName} to <b>1</b>,
# <br />- set {PasswordManager} to <b>none</b>.
# <br />These settings can be found in the <b>Security setup</b> section.

# **STRING 60**
# Name of auth token cookie.
$Foswiki::cfg{SsoLoginContrib}{AuthTokenName} = 'x-authtoken-cookie-name';

# **STRING 60**
# URL of SSO API to verify an auth token; %AUTHTOKEN% is set to the cookie value
# of the auth token.
$Foswiki::cfg{SsoLoginContrib}{VerifyAuthTokenUrl} = 'https://example.com/api/auth/%AUTHTOKEN%';

# **PERL 60**
# Some SSO APIs require to pass a key in the header of the http request to verify
# a auth token. Specify hash of the header-name => 'header value',
# such as:
# <pre>{ x-sso-api-key => 'API key value', x-any-other-name 'any other value'}</pre>
$Foswiki::cfg{SsoLoginContrib}{VerifyAuthTokenHeader} = {
         'x-sso-api-key' => 'API key value',
         };

# **STRING 60**
# Regular expression to extract the login name from the JSON response.
$Foswiki::cfg{SsoLoginContrib}{VerifyResponseLoginRE} = '"loginName":"([^"]*)';

# **STRING 60**
# Login URL; %ORIGURL% is set to the original URL where the user is sent after login.
$Foswiki::cfg{SsoLoginContrib}{LoginUrl} = 'https://example.com/login?redirect=%ORIGURL%';

# **STRING 60**
# Logout URL; %ORIGURL% is set to the original URL where the user is sent after logout.
$Foswiki::cfg{SsoLoginContrib}{LogoutUrl} = 'https://example.com/logout?redirect=%ORIGURL%';

