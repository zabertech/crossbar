# Nexus Database

The underlying datastore of Nexus is a heirarchal file store of YAML files.

## Basics

The Nexus database is stored as a series of `.yaml` files found in the `nexus/data/db` directory. The filename is used to identify the record in the system and further metadata can be found within each file.

Within Nexus v3, there are the following tables available (and their relationship to another record):

- `users`: Information associated with users that may connect and use the system
    - `apikeys`: API keys that allow the user to access the system without disclosing their password
    - `metadata`: Various bits of information associated with the user that might be useful in various ways
- `roles`: To manage the roles within the system (Currently only `trust`, `frontend`, and `backend`)
    - `uris`: The URIs that each roles are permitted to access and what type of action the role is permitted to perform

Any particular record within a table will at least have the following:

- `uuid` is an immutable identifier for a record regardless of table in the system. This is the critical identifier used by the system to track a record and used for actions such as `delete` and `udpate`. This is in fact a GUID creating via python's `uuid.uuid4()` then through `base64.urlsafe_b64encode()`. The following code demonstrates how the UUID is created:
    ```python
    import uuid
    import base64
    uid = uuid.uuid4().bytes
    # We have to take '==' off since base64 encoding of uuid
    # will leave 2 spare bytes. We don't care about this so
    # we simply trim it off
    uid_b64 = base64.urlsafe_b64encode(uid).decode('utf8')[:-2]
    print(uid_b64)
    ```
    If for any reason there is a need to convert to a binary UUID value, then the reverse can be performed
    ```python
    import base64
    # Restore the stripped `==` so that base64 decode can function again
    uuid_as_bytes = base64.urlsafe_b64decode(uid_b64 + '==')
    ```

- A mutable *key* value used to determine the filename stored on the system and has a useful purpose-specific meaning for the table (eg. `login` for users, `role` for roles). While the key values are unique for the local scope, they may change hence the need for both `uuid` and `key`

## ORM methods

For any table, the following methods are registered. However, due to the security impacts associated, some tables may not be accessible to all users (Some tables, such as `role` are only available to those with the `trust` role). As well, for some tables, such as `user`, only certain records and fields will be available for modification (again, for security reasons).

| URI Pattern | Purpose |
|-------------|---------|
|`com.izaber.wamp.system.db.query(tablename, condition list, fields=None, sort=None, limit=None, page=0)`|Fetches a set of records matching conditions from the table `tablename`|
|`com.izaber.wamp.system.db.create(parent_uuid, collection, data_rec)`|Create a new record in the table `tablename`|
|`com.izaber.wamp.system.db.update(uuid list, updates)`|Amends specific record information identified by the uuid|
|`com.izaber.wamp.system.db.delete(uuid list)`|Removes records that match the UUIDs|

## `system.db.query(tablename, condition list)`

When searching for records, two bits of information are important. What table to search from and what to filter by.

The default tables declared in the system are:

- `users`: Information associated with users that may connect and use the system
    - `apikeys`: API keys that allow the user to access the system without disclosing their password
    - `metadata`: Various bits of information associated with the user that might be useful in various ways
- `roles`: To manage the roles within the system (Currently only `trust`, `frontend`, and `backend`)
    - `uris`: The URIs that each roles are permitted to access and what type of action the role is permitted to perform



### Query Conditions

The basic structure of queries is mildly reminicent of OpenERP query domains, that is, building the queries using multiple arrays with a format like:

```python
[ "field_name", "operator", "comparison value" ]
```

For example, if we wanted to look for records where `revision` is greater than `10` we could craft a query domain like the following:

```python
[
    [ 'revision', '>', 10 ]
]
```

If we wanted to also ensure that `active` is true, we could add an additional query like so:

```python
[
    [ 'revision', '>', 10 ],
    [ 'active', '=', True ]
]
```

All the conditions must be met before the filter will allow a record to be returned so in this case, `revision` must be greater than 10 and `active` must be `True`.

#### Operations Available

The suite of available operations is fairly standard, there shouldn't be that many surprises in the list. Typecasting is automatic and handled by Python under the hood.

| Field | Operation   | Value Type | Description |
|-------|-------------|------------|-------------|
|`field`| `=`         | `str`, `int`, `bool` | Equal |
|`field`| `!=`        | `str`, `int` | Is Not Equal |
|`field`| `>=`        | `str`, `int` | Is Greater or Equal Than |
|`field`| `>`         | `str`, `int` | Is Greater Than |
|`field`| `<=`        | `str`, `int` | Is Less or Equal Then |
|`field`| `<`         | `str`, `int` | Is Less Than |
|`field`| `is`        | `str`, `int` | Is the same as |
|`field`| `in`        | `list` | Field value is in the list |
|`field`| `has`        | `str`, `int` | If field value is a list, checks if any elements match the right-side value `if right in (left): True`|
|`field`| `not in`    | `list` | Field value not found in list |
|`field`| `like`     | `str` | Field value contains the string<sup>1</sup> |
|`field`| `not like` | `str` | Field value does not contain the string<sup>1</sup> |
|`field`| `ilike`     | `str` | Field value case insensitive contains the string<sup>1</sup> |
|`field`| `not ilike` | `str` | Field value case insensitive does not contain the string<sup>1</sup> |

<sup>1</sup>: This is not SQL's `LIKE` operator. Currently this only does substring matches.

#### Complex Queries

##### OR
While the operations are fairly useful for individual field searches, it doesn't have quite the richness we're used to. To address that, there is support for `OR` queries as well.

Let's say we wanted to find `revisions` that are less than 11 as well as where `active` is `False`. With `OR` queries we can provide the following:

```python
[
    [
        'OR', [
            [ 'revision', '<', 11 ],
            [ 'active', '=', False ]
        ]
    ]
]
```

While the top level can still be interpreted as an `AND` clause, creating a new condition below it that is an `OR` condition will allow us to search on both options.

##### AND

As there may be `AND` conditions in `OR` conditions (and vice versa), it's possible to nest the clauses. For example, let's say we wanted to add one additional condition that we return if the `revision` is 10 and the record is also `active`. We can then to:

```python
[
    [
        'OR', [
            [ 'revision', '<', 11 ],
            [ 'active', '=', False ],
            [
                'AND',
                [
                    [ 'revision', '=', 10 ],
                    [ 'active', '=', True ],
                ]
            ]
        ]
    ]
]
```

##### NOT, NOR

Finally, there may be times where it's necessary to return the inverse of all the constraints. In that case, using the `NOT` operator is available. By wrapping a set of conditions with `NOT`, this treats the set of conditions like an "`AND`" grouping. If all conditions are `True`, the `NOT` condition will be `False`. If any conitions in the "`AND`" grouping are `False`, the group evaluates to `False` which in turn will cause the `NOT` to return a `True`.

```python
[
    [
        'NOT', [
            [ 'revision', '<', 11 ],
            [ 'active', '=', False ]
        ]
    ]
]
```

In some cases, the preference may be like `NOT(OR(condition1, condition2, condition3))`. For that, use the `NOR` operator. This will cause the condition to only return `True` if all the "`OR`" conditions are `False`.

```python
[
    [
        'NOR', [
            [ 'revision', '<', 11 ],
            [ 'active', '=', False ]
        ]
    ]
]
```

### Paging

This is **not** supported at the moment.

### Grouping

This is **not** supported at the moment.

### Aggregation Functions

This is **not** supported at the moment.

### Field Syntax

#### Basic Fields

The `field` argument of conditions has a particular syntax, which for the most part hopefully won't be surprising. The following is a test data file for the `zaber` user.

```yaml
## Database version. This key should always be present
version: 1

## Database Universal Unique Record ID
uuid: eVuM2uHLThGEC0KXQtOMpg

## Is the user allowed to access the bus? Note that if the
## setting is active yet the user is unable to authenticate from
## LDAP, the user will not be permitted to use the bus
enabled: true

## What role should be assigned to the user upon login
## by default we have been using "frontend". Can also be "backend"
## or "trust"
role: frontend

## What is the principle source of user metadata. Can be "ldap" to
## test against the ldap source or "local" for internal database
## This does not have any impact on keys which must be local regardless
source: ldap

## If the source is local, the hashed password is defined here. The passwords
## can be generated with
## import passlib.hash; print(passlib.hash.pbkdf2_sha256("password"))
password:

## If the source is local, email address of the entity
email:

## If the source is local, the userPrincipalName
upn: zaber@nexus

## If the source is local, the user's name
name:
```

One field that is not listed is the `key` which is determined from the the filesystem (prevents double entry of data). That will be listed as `login`.

As a JSON like object, the data can be represented thus:

```json
{
    login: "zaber",
    version: 1,
    uuid: "eVuM2uHLThGEC0KXQtOMpg",
    enabled: true,
    role: "frontend",
    source: "ldap",
    password: null,
    email: null,
    upn: "zaber@nexus",
    name: null
}
```

If the desire is to match on the `role` field, a condition like the following can be constructed:

```python
[
    [ "role", "=", "frontend" ]
]
```

Similarly, if the wish is to match on the `source` field:

```python
[
    [ "source", "=", "ldap" ]
]
```

## `system.db.create`

The creation of new records is fairly straight-forward.

## `system.db.update`

The updating of records is fairly straight-forward.

## `system.db.delete`

The deletion of records is fairly straight-forward.
