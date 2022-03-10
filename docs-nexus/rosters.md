# Rosters

## What is it?

Nexus offers a way of "registering" information against a shared name that gets removed after disconnection. Be aware that `registering` in the context of rosters is not like registering RPC calls. This is particularly useful when dealing with things that marshal a group of applications into a single location, things like:

- A roster of all dashboards available on WAMP
- A roster of all Zerp databases available on WAMP

The basic idea is that Nexus maintains a list that has pre-defined name such as `roster.dashboard:live`.

As different services connect, they add themselves to this list, via the `.system.roster.register` function. It's useful to add things such as "here's my name and the URL I live at".

When a service disconnects, intentionally or by network drop, Nexus will automatically remove the associated roster data. So data added to a roster is only present for as long as the service remains connected.

When someone needs to see a list of all available services associated with `roster.dashboard:live`, calling the `.system.roster.query` will return a list of all data entries associated with the roster name. The data returned is always associated with only actively connected sessions.

## Overview

### Server Side

As a ficticious example, let's assume an application called Zerp can have multiple variants running. There could be the production variant `live`, a sandbox `sandbox`, and a number of dev versions such as `dev-1`, and `dev-2`.

For a client, determining which services are available then becomes a bit of a challenge. Querying the list of all RPC URIs is not available unless the role is `trusted`. This is where the rosters become valuable.

A specific URI must be agreed upon by all entities. For the purpose of this example, we'll use `roster.zerp`.

Being able to register against this URI requires the `roster_ops` permission to be enabled. Much like the standard Nexus security permissions associated with URIs and roles `crsp`, there are two additional permissions `oq`. If the server happens to have a `backend` role, they will need to have a role URI permission equivalent to `o` on `roster.zerp`.

For the `backend` user, this can be done by editing the associated YAML file via filesystem or by GUI and adding:

```yaml
permissions:
- uri: roster.zerp
  perms: o
```

This will allow the server's session to register some arbitrary data to `roster.zerp` via the `.system.roster.register` RPC call. For example:

```python
ROSTER_NAME = 'roster.zerp'

data = {
    'databases': [
        {
            'database': 'live',
            'colour': 'flaming red',
            'description': 'Production McProductiony Face',
        }
    ]
}

wamp.call('system.roster.register',ROSTER_NAME,data)

# And then do server stuff
```

That should be sufficient to register the `data` block in the roster. Each of the other servers will need to do something similar.

### Client Side

Now, imagine that we're the client that needs to discover what databases are available. For that, the client's role must have the `roster_query` permission on `roster.zerp`. If the client has the role `frontend`, then the group yaml file will need something like:


```yaml
permissions:
# ...
# ... other permissions
# ...
- uri: roster.zerp
  perms: q
```

With just the `q` permission, a `frontend` user will not be able to register any entries to the `roster.zerp` entry. However, they will be able to ask for all entries associated with the roster name.

```python
ROSTER_NAME = 'roster.zerp'

records = wamp.call('system.roster.query',ROSTER_NAME)
entry = 1
for rec in records:
    print(entry, rec)
    entry += 1
```

For each registrated roster entry, a new `rec` is return. In this example the output might look like:

```python
1 { 'databases': [ { 'database': 'live', 'colour': 'flaming red', 'description': 'Production McProductiony Face', } ] }
2 ... and so on
3 ... and so forth
```

## Reference

### `system.roster.register` or `com.izaber.wamp.system.roster.register`

Parameters:

| Name | Required | Description |
|------|----------|-------------|
| `roster_name` | `Y` | The name of the roster in dot notation like URIs (also managed through the same system) |
| `data` | `Y` |  Arbitrary data to be stored with this roster entry |
| `visbility` | `N` |  Which roles are able to view this `[ role1, role2, etc ]` |

Registers `data` into the roster list named `roster_name`. This requires the `roster_ops` permission from the URI.

The default permissioning sets up roster names under the `roster.*` section, however, that's not a requirement and via the role permissions any URI can be used.

The `visibility` setting is a second level of control for determining who may be able to see the roster entry. By default the setting is `['*']`. This can be used to prevent access to certain roster entries even if by default the URI permissions allow the client to request it. This probably only going to be useful in later releases when we include LDAP groups and wish to hide certain entries from cluttering user's listings.

When the session disconnects, the roster entry is automatically removed.

Multiple calls to `system.roster.register` are allowed. However, the `data` segment will clobber the previous `data` entry with each call. A single roster entry is created for each combination of session and roster name. It is not possible for a single session to have multiple roster entries for a single roster name.

```python
ROSTER_NAME = 'roster.zerp'

data = {
    'databases': [
        {
            'database': 'live',
            'colour': 'flaming red',
            'description': 'Production McProductiony Face',
        }
    ]
}

wamp.call('system.roster.register',ROSTER_NAME,data)
```

Raises `swampyer.exceptions.ExInvocationError` upon permission error.

### `system.roster.unregister` or `com.izaber.wamp.system.roster.unregister`

| Name | Required | Description |
|------|----------|-------------|
| `roster_name` | `Y` | The name of the roster in dot notation like URIs (also managed throught he same system) |

This will remove the session's associated roster entry from the database. This would also happen if the session disconnects. It is not required to call the unregister before disconnecting.

```python
ROSTER_NAME = 'roster.zerp'

wamp.call('system.roster.unregister',ROSTER_NAME)
```

Raises `swampyer.exceptions.ExInvocationError` upon permission error.

### `system.roster.query` or `com.izaber.wamp.system.roster.query`

| Name | Required | Description |
|------|----------|-------------|
| `roster_name` | `Y` | The name of the roster in dot notation like URIs (also managed throught he same system) |

RPC will return a list of each roster entry matching the roster name and permitted via the `visibility` attribute. The contents of the data is arbitrary without any validation at the moment so wrapping things with an exception handler might be useful.

```python
ROSTER_NAME = 'roster.zerp'

records = wamp.call('system.roster.query',ROSTER_NAME)
for rec in records:
    print(rec)
```

Raises `swampyer.exceptions.ExInvocationError` upon permission error.



