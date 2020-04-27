import os
import sys
import re
import subprocess
import itertools
import argparse
import yaml

GENERATED = ".unknown"

TEMPLATE_PORT_LISTEN = """\
    listen << PORT_80_443 >>;
    server_name << DOMAIN_NAME >>;
"""

TEMPLATE_WELLKNOWN_LOCATION = """\
    location /.well-known/ {
        root << UNKNOWN_ROOT >>/<< DOMAIN_NAME >>/.well-known/;
    }
"""

TEMPLATE_SSL_CONFIG = """\
    add_header Strict-Transport-Security max-age=31536000;

    ssl_certificate << DOMAIN_PEM >>;
    ssl_certificate_key << DOMAIN_KEY >>;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256";      
    ssl_session_cache shared:SSL:50m;
    ssl_dhparam << UNKNOWN_ROOT >>/dhparam4096.pem;
    ssl_prefer_server_ciphers on;
"""

TEMPLATE_LOCATION_CHUNK = """\
    location /<< LOCATION >> {
        proxy_set_header    Host $host;
        proxy_set_header    X-Real-IP $remote_addr;
        proxy_set_header    X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header    X-Forwarded-Proto $scheme;

        proxy_pass          http://<< HOSTNAME >>:<< PORT >>;
        << REWRITE >>
        proxy_read_timeout  90;
    }
"""


def _templated(template, site, path=None, **kwargs):
    values = {k.upper(): value for k, value in kwargs.items()}

    values["DOMAIN_NAME"] = site
    values["UNKNOWN_ROOT"] = "/etc/nginx/unknown"
    values["DOMAIN_PEM"] = f"/etc/nginx/unknown/{site}/site.pem"
    values["DOMAIN_KEY"] = f"/etc/nginx/unknown/{site}/site.key"
    if path != None:
        segs = path[0].split("/", 1)
        if len(segs) == 1:
            domain, location = segs[0], ""
        else:
            domain, location = segs
        values["LOCATION"] = location
        values["PORT"] = path[1].get("port", 80)

    def replace(match):
        mgupper = match.group(1)
        if mgupper in values:
            return str(values[mgupper])
        print(f"Template match: {match.group(1)} not found", file=sys.stderr)
        return match.group(0)

    myrepls = re.sub("<< ([_A-Z0-9]+) >>", replace, template)
    return myrepls


def grouped_sites(config):
    domain = lambda url: url.split("/", 1)[0]

    sortlist = sorted(config.items())
    grouped = itertools.groupby(sortlist, key=lambda pair: domain(pair[0]))
    yield from grouped


def generate_configuration(filename, ssl=True, plain=False):
    configdir = os.path.dirname(os.path.realpath(filename))

    with open(filename, "r") as stream:
        config = yaml.safe_load(stream)
    confdir = os.path.join(configdir, GENERATED, "nginx", "conf.d")

    for site, paths in grouped_sites(config):
        port80_server = []
        port443_server = []

        port80_server.append(_templated(TEMPLATE_PORT_LISTEN, site, port_80_443=80))

        port443_server.append(
            _templated(TEMPLATE_PORT_LISTEN, site, port_80_443="443 ssl")
        )
        port443_server.append(_templated(TEMPLATE_SSL_CONFIG, site))

        for path in paths:
            hostname = "unknown-" + re.sub("[^a-zA-Z0-9]", "_", path[0])

            url = path[0]
            domain, basepath = url.split("/", 1) if "/" in url else (url, None)

            if basepath not in [None, ""]:
                rewrite = f"rewrite /{basepath}/(.*) /$1  break;"
            else:
                rewrite = ""

            if plain:
                port80_server.append(
                    _templated(
                        TEMPLATE_LOCATION_CHUNK,
                        site,
                        path=path,
                        hostname=hostname,
                        rewrite=rewrite,
                    )
                )
            port443_server.append(
                _templated(
                    TEMPLATE_LOCATION_CHUNK,
                    site,
                    path=path,
                    hostname=hostname,
                    rewrite=rewrite,
                )
            )

        port80_server = ["server {"] + port80_server + ["}\n"]
        port443_server = ["server {"] + port443_server + ["}\n"]

        if not os.path.exists(confdir):
            os.makedirs(confdir)
        outfile_site = os.path.join(confdir, site + ".conf")
        with open(outfile_site, "w") as conf:
            conf.write("\n".join(port80_server))
            if ssl:
                conf.write("\n".join(port443_server))


def generate_configuration_acme(filename):
    configdir = os.path.dirname(os.path.realpath(filename))

    with open(filename, "r") as stream:
        config = yaml.safe_load(stream)

    for site, paths in grouped_sites(config):
        port80_server = []
        port443_server = []

        port80_server.append(_templated(TEMPLATE_PORT_LISTEN, site, port_80_443=80))
        port80_server.append(_templated(TEMPLATE_WELLKNOWN_LOCATION, site))

        port80_server = ["server {"] + port80_server + ["}\n"]

        confdir = os.path.join(configdir, GENERATED, "nginx-acme")
        if not os.path.exists(confdir):
            os.makedirs(confdir)
        outfile_site = os.path.join(confdir, site + ".conf")
        with open(outfile_site, "w") as conf:
            conf.write("\n".join(port80_server))


TEMPLATE_SERVICE = """
[Unit]
Description=<< DOCKER_DESCR >>
Requires=docker.service
After=docker.service

[Service]
Restart=always
ExecStart=/usr/bin/docker start -a << DOCKER_TAG >>
ExecStop=/usr/bin/docker stop -t 10 << DOCKER_TAG >>

[Install]
WantedBy=local.target
"""


def generate_systemd_services():

    pass


def initialize_https(configdir):
    gen_key_script = """
openssl genrsa 4096 > unknown-root/account.key
openssl dhparam -out unknown-root/dhparam4096.pem 4096

openssl genrsa 4096 > unknown-root/<< DOMAIN_NAME >>.key
openssl req \
        -new \
        -sha256 \
        -key ./unknown-root/<< DOMAIN_NAME >>.key \
        -subj "/" \
        -reqexts SAN \
        -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:<< DOMAIN_NAME >>")) \
        > ./unknown-root/<< DOMAIN_NAME >>.csr
"""


def refresh_https():
    re_up_script = """
python acme_tiny.py --account-key ./account.key --csr ./<< DOMAIN_NAME >>.csr --acme-dir /usr/share/nginx/<< DOMAIN_NAME >>/.well-known/acme-challenge > ./signed-<< DOMAIN_NAME >>.crt
# wget https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem -O ./lets-encrypt-x3-cross-signed.pem
cat signed-<< DOMAIN_NAME >>.crt lets-encrypt-x3-cross-signed.pem > chained-<< DOMAIN_NAME >>.pem
"""

    "service nginx restart"

    pass


def restart(service):
    os.system("service << >> stop")
    os.system("service << >> start")


def run_dev(filename):
    # run all the dockers in a non-ssl env for testing

    configdir = os.path.dirname(os.path.realpath(filename))

    with open(filename, "r") as stream:
        config = yaml.safe_load(stream)
    confdir = os.path.join(configdir, GENERATED, "nginx", "conf.d")

    runname = "abcd"

    for url, siteconfig in config.items():
        # run a docker container for each backing server
        print(siteconfig["image"])

        name = "unknown-" + re.sub("[^a-zA-Z0-9]", "_", url)

        args = [
            "docker",
            "run",
            "--rm",
            "-d",
            "-l",
            runname,
            "--name",
            name,
            "--hostname",
            name,
            "--network",
            "mynet",
            siteconfig["image"],
        ]
        print(" ".join(args))

        subprocess.run(args)

    args = [
        "docker",
        "run",
        "--rm",
        "-d",
        "--name",
        "unknown-nginx-server",
        "-p",
        "80:80",
        "--network",
        "mynet",
        "-l",
        runname,
        "-v",
        f"{confdir}:/etc/nginx/conf.d",
        "nginx",
    ]

    print(" ".join(args))
    subprocess.run(args)

    print(
        f"services running:  stop with\n"
        f'docker stop `docker ps --filter "label={runname}" -q `'
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="<unknown>: from docker to https")
    subparsers = parser.add_subparsers(dest="operation")

    setup = subparsers.add_parser(
        "setup", help="prepare configuration directory and SSL keys"
    )
    setup.add_argument("-f", "--file", required=True, help="configuration yaml file")

    run = subparsers.add_parser("run", help="run the server")
    run.add_argument("-f", "--file", required=True, help="configuration yaml file")
    # run.add_argument("-d", "--dir", required=True, help="configuration directory")

    ssl_update = subparsers.add_parser("ssl-update", help="refresh the https from acme")

    args = parser.parse_args()

    if args.operation == None:
        parser.print_help()
    elif args.operation == "setup":
        configdir = os.path.dirname(os.path.realpath(args.file))
        generate_configuration(args.file, ssl=False, plain=True)
        generate_configuration_acme(args.file)
        initialize_https(configdir)
    elif args.operation == "run":
        run_dev(args.file)
    elif args.operation == "ssl-update":
        refresh_https()
