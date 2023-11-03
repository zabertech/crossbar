
DEFAULT_ROLE = 'frontend'
LOCAL_UPN_DOMAIN = 'nexus'

PERM_DENY = 0
PERM_ALLOW = 1
PERM_REQUIRE_ELEVATED = -1
PERM_REQUIRE_DOCUMENTATION = -2

TRAITS = [
    [ 'require_documentation', '!' ],
    [ 'require_elevated', '+' ],
]
TRAIT_TO_NAME = {}
TRAIT_TO_CODE = {}
for trait_name, trait_code in TRAITS:
    TRAIT_TO_NAME[trait_code] = trait_name
    TRAIT_TO_CODE[trait_name] = trait_code
TRAIT_REGEX = r"["+"".join(TRAIT_TO_NAME.keys())+r"]*"


PERMS = [
    [ 'call', 'c' ],
    [ 'register', 'r' ],
    [ 'subscribe', 's' ],
    [ 'publish', 'p' ],
    [ 'roster_ops', 'o' ],
    [ 'roster_query', 'q' ],
]
PERM_TO_NAME = {}
PERM_TO_CODE = {}
for perm_name, perm_code in PERMS:
    PERM_TO_NAME[perm_code] = perm_name
    PERM_TO_CODE[perm_name] = perm_code
PERM_REGEX = r"([" + "".join(PERM_TO_NAME.keys()) + f"])({TRAIT_REGEX})"

ELEVATED_STALE_SECONDS = 120

AUTH_SOURCE_LOCAL = 'local'
AUTH_SOURCE_APIKEY = 'apikey'
AUTH_SOURCE_LDAP = 'ldap'
AUTH_SOURCE_OTP = 'otp'

SECONDS_IN_MINUTE = 60
SECONDS_IN_HOUR = SECONDS_IN_MINUTE * 60
SECONDS_IN_DAY = SECONDS_IN_HOUR * 24
SECONDS_IN_WEEK = SECONDS_IN_DAY * 7

SESSION_STALE_SECONDS = SECONDS_IN_WEEK

# Sessions can last 7 days
SESSION_LIFESPAN = SECONDS_IN_DAY * 7

TZ = 'America/Vancouver'

# Prefixes for locally registered things

WAMP_LOCAL_REGISTRATION_PREFIX = 'com.izaber.wamp'
WAMP_LOCAL_SUBSCRIPTION_PREFIX = 'com.izaber.wamp'
