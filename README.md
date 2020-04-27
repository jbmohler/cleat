# unknown

You have docker containers with HTTP servers.  You want them exposed on the open web.  Here is a tool that does just that with SSL and a production ready reverse proxy.  This goal is delivered by using letsencrypt and nginx.

This project is heading for a new name of `cleat`. The goal is "from docker
to https in 60 seconds or less"

# goals

* minimal declarative syntax (basically bind **domain name** to **port number**, likely also include optional **path** and **environment variables**)
* takes care of SSL & certificates
* define multiple domain names and multiple back-ends per domain in the configuration file.
* serves only https
* prefer docker services

# aspirational usage

Define your configuration in one easy config.yaml.

```sh
cleat run config.yaml
```

If you want to just prepare the setup.

```sh
cleat setup config.yaml
```

To run a development server.

```sh
cleat run config.yaml --no-ssh --plain
```

To update the SSL certificates (from letsencrypt).

```sh
cleat update-ssl config.yaml
```

# implemenation sketch

read a yaml file and create the sites-available/sites-enabled configuration files in an nginx configuration to reverse proxy for each of the configured sites.

for each configured domain name, set up a lets-encrypt certificate and configure the nginx configuration accordingly

set the docker file to run on startup with systemd scripts (or whatever it is debian default uses)