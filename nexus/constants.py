
DEFAULT_ROLE = 'frontend'
LOCAL_UPN_DOMAIN = 'nexus'

PERM_DENY = 0
PERM_ALLOW = 1
PERM_REQUIRE_ELEVATED = -1

ELEVATED_STALE_SECONDS = 120

AUTH_SOURCE_LOCAL = 'local'
AUTH_SOURCE_APIKEY = 'apikey'
AUTH_SOURCE_LDAP = 'ldap'

SESSION_STALE_SECONDS = 60*60*24*7

# Sessions can last 7 days
SESSION_LIFESPAN = 3600 * 24 * 7

TZ = 'America/Vancouver'

# Prefixes for locally registered things

WAMP_LOCAL_REGISTRATION_PREFIX = 'com.izaber.wamp'
WAMP_LOCAL_SUBSCRIPTION_PREFIX = 'com.izaber.wamp'

