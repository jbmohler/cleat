# cleat

*Take your docker containers to https in 60 seconds or less.*

You have docker containers with HTTP servers.  You want them exposed on the
open web.  Here is a tool that does just that with SSL and a production ready
reverse proxy.  This goal is delivered by using letsencrypt and nginx.

Cleat configured servers currently score an A or A+ at
https://www.ssllabs.com/ssltest/ .

# goals

* minimal declarative syntax - basically bind **domain name** to **port
  number**
* takes care of SSL & certificates
* define multiple domain names and multiple back-ends per domain in the
  configuration file.
* serves only https
* prefer docker services

# features included

* optionally specify **mounts**
* optionally specify **environment variables**
* use the current user rather than root for the individual images for each site
  (optionally specify "root" or a specific user with the "user" config option)
* single site restart command

# likely road-map

* dev/test mode with no ssl
* debian buster compatible init scripts
* switch nginx for haproxy (should be transparent to config.yaml)

# usage

Define your configuration in one easy config.yaml.

An example config.yaml

```json
mysite.com:
    image: mysite-static:latest

mysite.us/app1:
    image: appflask:latest
    port: 5000
    user: www
    environment:
        DBURL: postgresql://user:password@myhost/db
        CONFIG_VAR1: fast-mode
    mounts:
        /path/to/dir: /container/dir
```

Run the server with.

```sh
cleat run -f config.yaml
```

If you want to just prepare the setup.

```sh
cleat setup -f config.yaml
```

To update the SSL certificates (from letsencrypt).

```sh
cleat update-ssl -f config.yaml
```

To restart a specific instance

```sh
cleat instance-restart mysite.us/app1
```

To stop a running server

```sh
cleat stop
```

# aspirational usage

To run a development server.

```sh
cleat run -f config.yaml --no-ssh --plain
```

# implementation sketch

read a yaml file and create the sites-available/sites-enabled configuration
files in an nginx configuration to reverse proxy for each of the configured
sites.

for each configured domain name, set up a lets-encrypt certificate and
configure the nginx configuration accordingly

set the docker file to run on startup with systemd scripts (or whatever it is
debian default uses)
