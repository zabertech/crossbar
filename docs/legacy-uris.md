# Legacy API

Nexus v2 had a suite of in-built registered methods that were used in tools such as the dashboard.

Listed are the known URIs that existed on the system

## API Keys

| URI (com.izaber.wamp prefix) | Transitional URI | Upgrade Path<sup>*</sup> | Purpose |
|------------------------|-----------|----|-----|
|.api_key.list_keys(user)|.my.apikey.list()|.system.db.query|
|.api_key.create_key(user, vals)|.my.apikey.create(vals)|.system.db.create|
|.api_key.delete_key(user, key)|.my.apikey.delete(key)|.system.db.delete|

<sup>*</sup> for querying other users' API Key information

## Preferences

| URI (com.izaber.wamp prefix) | Transitional URI | Upgrade Path<sup>*</sup> | Purpose |
|------------------------|-----------|----|-----|
|.preference.get(key)|.my.metadata.get(key)|.system.db.query||
|.preference.set(key, value)|.my.metadata.set(key, value)|.system.db.update||
|.preference.remove(key)|.my.metadata.delete(key)|.system.db.delete||
|.preference.filter(searchFilter)|.my.metadata.query(key)|.system.db.query|

<sup>*</sup> for querying other users' API Key information

## Directory

| URI (com.izaber.wamp prefix) | Transitional URI | Upgrade Path | Purpose |
|------------------------|-----------|----|-----|
|.directory.users()|.directory.ldap.users()|.system.user.query||
|.directory.groups()|.directory.ldap.groups()|REMOVED|

## Authentication Related

| URI (com.izaber.wamp prefix) | Transitional URI | Upgrade Path | Purpose |
|------------------------|-----------|----|-----|
|.directory.authenticate(login, password)|.auth.authenticate(username, password)|.auth.authenticate(username, password)||
|.system.reauthenticate(password)|.auth.reauthenticate(password)|.auth.reauthenticate(password)|
|.system.is_reauthenticated()|.auth.is_reauthenticated()|.auth.is_reauthenticated()|
|.system.extend_reauthenticate()|.auth.extend_reauthenticate()|.auth.extend_reauthenticate()|

## Email

| URI (com.izaber.wamp prefix) | Transitional URI | Upgrade Path | Purpose |
|------------------------|-----------|----|-----|
|.email.send(recipient, subject, message, options={})|.email.send(recipient, subject, message, options={})||
