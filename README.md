# Crossbar.io with iZaber Nexus patches

Crossbar.io with modifications is what we use internally to handle the internal RPC/pubsub requirements in the organization.

Attempts were made to minimize the number of modifications made to Crossbar so that future changes can be merged as well as for future compatiblity for security patches and so on.

Differences to mainline/additions:

- Built to be used from a docker container running under PyPy3.
- File-based ORM for handling data
- Support for LDAP syncronization
- Local user support
- Cookie handling managed on disk
- Support for session lifetime data associated with a share token (useful for collating microservices)
- Additional security handling for URIs
- Web-based front-end for management
- Command-line tool for managing the local database
- Fast developer environment within a docker container
- Fast deploy via docker container

## Quick Start

The primary development/host environment for this customization has been [Ubuntu Server 20.04](https://releases.ubuntu.com/20.04/). While the apt repo copy should work, usually the latest official [Docker Instructions](https://docs.docker.com/desktop/linux/install/ubuntu/).

1. Check out this repository `git clone https://github.com/zabertech/crossbar.git`
2. Build and login to the container by running `./run.sh login`
3. Install crossbar from root using `sudo pypy3 setup.py install` [Reason](#warning)
4. Once in the container, create the new database: `nexus devdb create --cbdir data your_admin_user your_admin_password`
5. Run the server with `./run-server.sh`
6. Connect to crossbar by going to `http://your.host.ip:8282`
7. Login with `your_admin_user` and `your_admin_password`

Logs from the server can be found in `./data/node.log`

### Configuration

#### Invocation

When using the `run.sh` script, the script will launch with the following properties:

```bash
  docker run --name $CONTAINER_NAME \
      -ti \
      -v `pwd`:/app \
      -p $PORT_PLAINTEXT:8282 \
      -p $PORT_SSL:8181 \
      $LAUNCH_MODE \
      $IMAGE_NAME /app/run-server.sh"
```

The various variables are defined by default as thus:

```
IMAGE_NAME=izaber/nexus
CONTAINER_NAME=nexus
CBDIR=/app/data
LOG_LEVEL=debug
LOG_COLOURS=true
LOG_FORMAT=tandard
PORT_PLAINTEXT=8282
PORT_SSL=4430
```

The values can be overriden by simply defining them before calling `run.sh`.

#### izaber.yaml

Crossbar's standard `config.conf` has been patched to use the `izaber.yaml` file located within the `./data` directory instead.

Upon creating the devdb, a sample `./data/izaber.yaml` has been created. It holds the required information for things such as:

- LDAP credentials
- Startup Vacuum/Sync (Usually not valuable)
- Crossbar transport configuration
- Configuration of crossbar components

#### SSL support

While crossbar does offer SSL support natively, there has been some issues with errors such as:

```
2022-05-24T00:05:03+0000 [Router         14] SSL error: unexpected eof while reading (in )
2022-05-24T00:05:03+0000 [Router         14] Router detached session from realm "izaber" (session=5373326675186837, detached_session_ids=1, authid="wamp-email-ingestor", authrole="backend", authmethod="ticket", authprovider="dynamic") <crossbar.router.router.RouterBase.detach>
2022-05-24T00:05:03+0000 [Router         14] <autobahn.twisted.websocket.WebSocketAdapterProtocol.connectionLost> connection lost for peer="tcp4:10.2.2.142:60756", closed with error [Failure instance: Traceback: <class 'OpenSSL.SSL.Error'>: [('SSL routines', '', 'unexpected eof while reading')]
/usr/local/lib/pypy3.8/dist-packages/twisted/internet/posixbase.py:297:_disconnectSelectable
/usr/local/lib/pypy3.8/dist-packages/twisted/internet/tcp.py:309:readConnectionLost
/usr/local/lib/pypy3.8/dist-packages/twisted/internet/tcp.py:326:connectionLost
/usr/local/lib/pypy3.8/dist-packages/twisted/protocols/tls.py:395:connectionLost
--- <exception caught here> ---
/usr/local/lib/pypy3.8/dist-packages/twisted/protocols/tls.py:275:_flushReceiveBIO
/usr/local/lib/pypy3.8/dist-packages/OpenSSL/SSL.py:1865:recv
/usr/local/lib/pypy3.8/dist-packages/OpenSSL/SSL.py:1700:_raise_ssl_error
/usr/lib/pypy3.8/_functools.py:80:__call__
/usr/local/lib/pypy3.8/dist-packages/OpenSSL/_util.py:55:exception_from_error_queue
```

Proxying requests via nginx for SSL has been the most reliable.

Example nginx conf:

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    server_name example.com;

    ssl_certificate /etc/ssl/private/ssl-bundle.crt;
    ssl_certificate_key /etc/ssl/private/ssl.key;

    ssl_session_timeout 1d;
    ssl_session_cache shared:MozSSL:10m;  # about 40000 sessions
    ssl_session_tickets off;

    # intermediate configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;


    # HSTS (ngx_http_headers_module is required) (63072000 seconds)
    add_header Strict-Transport-Security "max-age=63072000" always;

    # replace with the IP address of your resolver
    resolver 127.0.0.1;

    location / {
        proxy_pass http://172.17.0.1:8282/;
    }

    location /ws {
        proxy_pass http://172.17.0.1:8282/ws;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Real-Ip $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }
}
```

## Development

### Quick Start

Follow the standard **Quick Start** steps from above.

### Running Tests

1. Enter the container with `./run.sh login`
2. Go into the tests directory: `cd tests`
3. Execute tests: `sudo ./run-tests.py`

<span id="warning"></span>
**Warning:** There is an issue in the docker build. If you run into any issues when running the tests and see that the `crossbar` binary cannot be loaded, you can run this command in the crossbar project root to fix it:

```sh
sudo pypy3 setup.py install
```

### Editing Files

- Source is located at `/app`. Crossbar/Nexus has been installed in `develop` mode so editing the source in `/app` will impact future runs without needing to reinstall
- `vim-nox` has been packaged into the container so it's possible to edit code 

## Architecture

### Files

Most of Zaber's code is found in the directory `./nexus`.

### Database

The database is a non-standard file-based database. Each record is a single YAML file on the filesystem. Modifications to the records can be done by modifying the records. Direct editing of a record using a text editor is also permissible as the system will detect changes upon save and reload.

The location of the database can be found at `.../data/db/`. The current models being used by the system are:


- apikeys
- cookies
- metadata
- registrations
- roles
- rosters
- uris
- users


