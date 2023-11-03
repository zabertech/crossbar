# Nexus On-Time-Passwords

Using one time passwords

## Basics

One-Time Passwords are passwords that when created have a time-limited window for use then when used to log into an account, get removed from further use.

These passwords can be created by the user to delegate credentials temporarily to another server or can created by a trusted user to perform actions for another user.

## `com.izaber.wamp.my.otp.create()`

Creates a new personal OTP and returns a dictionary for further usage elsewhere.

The OTP created will have a lifetime of 10 minutes.

Returns a dict with the fields:

| Field | Type | Example | Description |
|-------|------|---------|-------------|
| `plaintext_key` | `str` | `'i047jcfUWQQugakMVB8bzwuFjikDwZ-d'` | The key that can be used to login |
| `login` | `str` | `'kristen98'` | Login/AuthID to be used for logging in|
| `uuid` | `str` | `'dgvlMoyfS3WkIrP0xACV6g'` | UUID of the record on system |
| `origin` | `str` | `'kristen98@127.0.0.1'` | Who requested the OTP |
| `expires` | `str` | `'2023-10-17T10:17:30.805300-07:00'` | When the API key gets reaped (if left unused) |
| `permissions` | `list` | `[]` | Additional restrictions on the key |
| `key` | `str` | `'nHiqIwUZgxPUOnUrpWuDoafGwGMoQQPpv69_VzudkB0'` | Digest key (not useful aside for nexus ) |
| `owner` | `str` | `'XS7u8o8PReSoZiJqb6gp-g'` | UUID of who the key belonges to |


Basic Example:

```python
from izaber import initialize
from izaber_wamp import wamp

import swampyer

initialize()

otp = wamp.call('my.otp.create')

login = otp['login']
plaintext_key = otp['plaintext_key']

new_client = swampyer.WAMPClientTicket(
                url="wss://nexus.izaber.com/ws",
                realm="izaber",
                username=login,
                password=plaintext_key,
            ).start()

print(new_client.call('com.izaber.wamp.auth.whoami'))
```

## `com.izaber.wamp.system.otp.create(login:str, data_rec:dict=None)`

This call is only available to accounts with `trust` level access. This allows the creation of single use passwords for another user.

The OTP created will have a lifetime of 10 minutes.

While it is possible to create a key different than 10 minutes via the `data_rec` argument. See below:

Returns a dict with the fields:

| Field | Type | Example | Description |
|-------|------|---------|-------------|
| `plaintext_key` | `str` | `'i047jcfUWQQugakMVB8bzwuFjikDwZ-d'` | The key that can be used to login |
| `login` | `str` | `'kristen98'` | Login/AuthID to be used for logging in|
| `uuid` | `str` | `'dgvlMoyfS3WkIrP0xACV6g'` | UUID of the record on system |
| `origin` | `str` | `'kristen98@127.0.0.1'` | Who requested the OTP |
| `expires` | `str` | `'2023-10-17T10:17:30.805300-07:00'` | When the API key gets reaped (if left unused) |
| `permissions` | `list` | `[]` | Additional restrictions on the key |
| `key` | `str` | `'nHiqIwUZgxPUOnUrpWuDoafGwGMoQQPpv69_VzudkB0'` | Digest key (not useful aside for nexus ) |
| `owner` | `str` | `'XS7u8o8PReSoZiJqb6gp-g'` | UUID of who the key belonges to |


Basic Example:

```python
from izaber import initialize
from izaber_wamp import wamp

import swampyer

initialize()

ANOTHER_USER = 'jsmith1234'

otp = wamp.call('system.otp.create', ANOTHER_USER)

login = otp['login']
plaintext_key = otp['plaintext_key']

new_client = swampyer.WAMPClientTicket(
                url="wss://nexus.izaber.com/ws",
                realm="izaber",
                username=login,
                password=plaintext_key,
            ).start()

print(new_client.call('com.izaber.wamp.auth.whoami'))
```

To use an alternate expiry timeframe, amending the call to the following works:

```python

from izaber import initialize
from izaber_wamp import wamp

import datetime
import pytz
import swampyer

localtz = pytz.timezone('America/Vancouver')
now = datetime.datetime.now(localtz)

initialize()

ANOTHER_USER = 'jsmith1234'

# 10 second timeout
expires = now + datetime.timedelta(seconds=10)

# Setup the data record
data_rec = { 'expires': expires }

# Make the cookie
otp = wamp.call('system.otp.create', ANOTHER_USER, data_rec)

new_client = swampyer.WAMPClientTicket(
                url="wss://nexus.izaber.com/ws",
                realm="izaber",
                username=login,
                password=plaintext_key,
            ).start()

print(new_client.call('com.izaber.wamp.auth.whoami'))
```


