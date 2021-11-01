# Remote Procedure Calls

## Basics

###  Example
Assuming that the user has permission to register RPC functions on the bus, using something like swampyer will allow code like the following:

```python
import swampyer
import time

def hello(invoke, name):
    return f"Hello {name}!"

client = swampyer.WAMPClientTicket(
                url="ws://localhost:8282/ws",
                realm="realm",
                username='user',
                password='password'
            ).start()


client.register(
            'my.uri.for.my.function',
            hello,
            details={
                    "match": u"prefix",
                    "force_reregister": True,
                    # ... just example options
                }
        )

# Do something else or just hangout here. When the program ends,
# the registration will also be removefd
while True:
    time.sleep(1)
```

Then, to call this registered function it's possible to do the following

```python
import swampyer

client = swampyer.WAMPClientTicket(
                url="ws://localhost:8282/ws",
                realm="realm",
                username='user',
                password='password'
            ).start()


result = client.call('my.uri.for.my.function', 'my name')
print(result)
```

The value of `result` should then be `"Hello my name!"`.

## Permissions

For clients registering a uri, the authenticated user's role must have `registration` permissions allowed on the uri.

For clients that are calling the uri, the authenticated user's role must have `call` permissions allowed on the uri.

## Special Permissions

### Documentation Required

In certain cases we may want to ensure that the registered function has more of a "paper trail".

By setting up the permission with requires documentation like `r!`, this will force a URI to have a populated entry in the database before it is allowed to be available.

As an example, if the URI `'com.example.func'` required documentation for the `frontend` role via the rule such as:

`com.example.*` = `cr!`

Without a database entry, an attempt to register the function will be denied.

```
```








