# URIs

## Nexus URI pattern matching

Nexus has serveral options for nodes when doing URI matching

- exact: `com.izaber.wamp.example.uri`
- wildcard: `com.izaber.wamp.example.*` - This will match anthing that starts with `com.izaber.wamp.example.` note that the wildcard is only avaiable to be used for an entire group
- regex matching: `com.izaber.wamp.example./prefix.*/` - This will match similar to `com.izaber.wamp.example.prefix-some-other-words` but not `com.izaber.wamp.example.prefix-some-other-words.more-words` to match the second option you'd need to do `com.izaber.wamp.example./prefix.*/.*`

You can check test folder for examples uris and expected outcomes: [matching test](../tests/test_01-trie.py)


## Nexus System URIs

### Authentication
| URI Pattern | Purpose |
|-------------|---------|
|`com.izaber.wamp.auth.authorizer`||
|`com.izaber.wamp.auth.authenticator`||
|`com.izaber.wamp.auth.whoami`||

### Elevated Authentication
| URI Pattern | Purpose |
|-------------|---------|
|`com.izaber.wamp.auth.reauthenticate`||
|`com.izaber.wamp.auth.reauthenticate_expire`||
|`com.izaber.wamp.auth.is_reauthenticated`||
|`com.izaber.wamp.auth.extend_reauthenticate`||
|`com.izaber.wamp.auth.refresh_authorizer`||

### Database ORM

| URI Pattern | Purpose |
|-------------|---------|
|`com.izaber.wamp.system.db.query(tablename, condition list, fields=None, sort=None, limit=None, page=0)`|Fetches a set of records matching conditions from the table `tablename`|
|`com.izaber.wamp.system.db.create(parent_uuid, collection, data_rec)`|Create a new record in the table `tablename`|
|`com.izaber.wamp.system.db.update(uuid list, updates)`|Amends specific record information identified by the uuid|
|`com.izaber.wamp.system.db.delete(uuid list)`|Removes records that match the UUIDs|

