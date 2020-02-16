# unknown
a tool for putting docker based http servers behind nginx

# goals

* minimal declarative syntax (basically bind **domain name** to **port number**, likely also include optional **path** and **environment variables**)
* takes care of SSL & certificates
* serves only https
* prefer docker services

# implemenation sketch

read a yaml file and create the sites-available/sites-enabled configuration files in an nginx configuration to reverse proxy for each of the configured sites.

for each configured domain name, set up a lets-encrypt certificate and configure the nginx configuration accordingly

set the docker file to run on startup with systemd scripts (or whatever it is debian default uses)
