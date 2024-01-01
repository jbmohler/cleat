import os
import sys
import json
import re
import glob
import random
import subprocess
import itertools
import yaml

GENERATED = ".cleat"

TEMPLATE_PORT_LISTEN = """\
    listen << PORT_80_443 >>;
    server_name << DOMAIN_NAME >>;
"""

TEMPLATE_LOCATION_REDIR_HTTPS = """\
    location /<< LOCATION >> {
        return 301 https://<< DOMAIN_NAME >>$request_uri;
    }
"""

TEMPLATE_WELLKNOWN_LOCATION = """\
    location /.well-known/ {
        root /usr/share/nginx/<< DOMAIN_NAME >>/;
    }
"""

TEMPLATE_SSL_CONFIG = """\
    add_header Strict-Transport-Security max-age=31536000;

    ssl_certificate << CLEAT_ROOT >>/chained-<< DOMAIN_NAME >>.pem;
    ssl_certificate_key << CLEAT_ROOT >>/<< DOMAIN_NAME >>.key;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256";
    ssl_session_cache shared:SSL:50m;
    ssl_dhparam << CLEAT_ROOT >>/dhparam4096.pem;
    ssl_prefer_server_ciphers on;
"""

TEMPLATE_LOCATION_CHUNK = """\
    location /<< LOCATION >> {
        proxy_set_header    Host $host;
        proxy_set_header    X-Real-IP $remote_addr;
        proxy_set_header    X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header    X-Forwarded-Proto $scheme;
        proxy_set_header    X-Original-URI $request_uri;
        # https://stackoverflow.com/questions/13672743/eventsource-server-sent-events-through-nginx
        proxy_set_header Connection '';
        proxy_cache_bypass $http_upgrade;
        proxy_buffering off;
        proxy_cache off;
        chunked_transfer_encoding off;

        proxy_pass          http://<< HOSTNAME >>:<< PORT >>;
        << REWRITE >>
        proxy_read_timeout  90;
    }
"""


def _templated(template, site, path=None, **kwargs):
    values = {k.upper(): value for k, value in kwargs.items()}

    values["DOMAIN_NAME"] = site
    values["CLEAT_ROOT"] = "/etc/nginx/cleat"
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
    def domain(url):
        return url.split("/", 1)[0]

    sortlist = sorted(config.items())
    grouped = itertools.groupby(sortlist, key=lambda pair: domain(pair[0]))
    yield from grouped


def generate_configuration(filename, ssl=True, plain=False):
    configdir = os.path.dirname(os.path.realpath(filename))

    with open(filename, "r") as stream:
        config = yaml.safe_load(stream)
    confdir = os.path.join(configdir, GENERATED, "nginx", "conf.d")

    # Original list of conf files, clean up extras after the fact.
    conf_files = glob.glob(os.path.join(confdir, "*.conf"))
    generated = []

    for site, paths in grouped_sites(config):
        port80_server = []
        port443_server = []

        port80_server.append(_templated(TEMPLATE_PORT_LISTEN, site, port_80_443=80))
        port80_server.append(_templated(TEMPLATE_WELLKNOWN_LOCATION, site))

        port443_server.append(
            _templated(TEMPLATE_PORT_LISTEN, site, port_80_443="443 ssl")
        )
        port443_server.append(_templated(TEMPLATE_SSL_CONFIG, site))

        for path in paths:
            hostname = "cleat-" + re.sub("[^a-zA-Z0-9]", "_", path[0])

            url = path[0]
            domain, basepath = url.split("/", 1) if "/" in url else (url, None)

            def _truthy(d, key):
                return d.get(key, True) not in ("false", "0", False)

            if basepath not in [None, ""] and _truthy(path[1], "rewrite_prefix"):
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
            else:
                port80_server.append(
                    _templated(
                        TEMPLATE_LOCATION_REDIR_HTTPS,
                        site,
                        path=path,
                        hostname=hostname,
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
        generated.append(outfile_site)

    for extra in set(conf_files).difference(generated):
        print(f"Removing extra {extra}")
        os.unlink(extra)


def generate_configuration_acme(filename):
    configdir = os.path.dirname(os.path.realpath(filename))

    with open(filename, "r") as stream:
        config = yaml.safe_load(stream)

    for site, paths in grouped_sites(config):
        port80_server = []

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


def initialize_https(filename):
    with open(filename, "r") as stream:
        config = yaml.safe_load(stream)
    configdir = os.path.dirname(os.path.realpath(filename))
    httpsdir = os.path.join(configdir, GENERATED, "https")

    if not os.path.exists(httpsdir):
        os.mkdir(httpsdir)
    os.chdir(httpsdir)

    singleton_script = """
openssl genrsa 4096 > account.key
openssl dhparam -out dhparam4096.pem 4096
"""

    def base_file_exists(fn):
        return os.path.exists(os.path.join(fn))

    if base_file_exists("account.key") and base_file_exists("dhparam4096.pem"):
        print("Using cached account.key and dhparam4096.pem")
    else:
        subprocess.run(singleton_script, shell=True)

    gen_key_script = """
openssl genrsa 4096 > << DOMAIN_NAME >>.key
openssl req \
        -new \
        -sha256 \
        -key << DOMAIN_NAME >>.key \
        -subj "/" \
        -reqexts SAN \
        -config <(cat /etc/ssl/openssl.cnf <(printf "[SAN]\nsubjectAltName=DNS:<< DOMAIN_NAME >>")) \
        > << DOMAIN_NAME >>.csr
"""

    self_sign_script = """
openssl x509 \
        -req -days 365 -in << DOMAIN_NAME >>.csr \
        -signkey << DOMAIN_NAME >>.key \
        -out << DOMAIN_NAME >>.crt
cat << DOMAIN_NAME >>.key << DOMAIN_NAME >>.crt > chained-<< DOMAIN_NAME >>.pem
"""

    for site, paths in grouped_sites(config):
        print(site)
        site_key_file = _templated("<< DOMAIN_NAME >>.key", site)
        site_csr_file = _templated("<< DOMAIN_NAME >>.csr", site)
        if base_file_exists(site_key_file) and base_file_exists(site_csr_file):
            print(f"Using cached {site_key_file} and {site_csr_file}")
        else:
            gkey = _templated(gen_key_script, site)
            subprocess.run(gkey, shell=True, executable="/bin/bash")

        chained_pem_file = _templated("chained-<< DOMAIN_NAME >>.pem", site)
        if base_file_exists(chained_pem_file):
            print(f"Using cached or acme acquired {chained_pem_file}")
        else:
            ssign = _templated(self_sign_script, site)
            subprocess.run(ssign, shell=True, executable="/bin/bash")

    curl_cross = "curl https://letsencrypt.org/certs/lets-encrypt-r3-cross-signed.pem -o ./lets-encrypt-r3-cross-signed.pem"
    subprocess.run(curl_cross, shell=True)


def _start_acme_server(confdir, httpsdir):
    alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
    runname = "".join([random.choice(alpha) for x in range(8)])

    args = [
        "docker",
        "run",
        "--detach",
        "--name",
        "cleat-nginx-server",
        "-p",
        "80:80",
        "-l",
        runname,
        "-v",
        f"{confdir}:/etc/nginx/conf.d",
        "-v",
        f"{httpsdir}:/usr/share/nginx/",
        "nginx",
    ]

    # print(" ".join(args))
    subprocess.run(args)
    return runname


def _stop_acme_server(runname):
    cmd = f'docker stop `docker ps --filter "label={runname}" -q `'
    # print(cmd)
    subprocess.run(cmd, shell=True)
    cmd = f'docker container rm `docker ps --all --filter "label={runname}" -q `'
    # print(cmd)
    subprocess.run(cmd, shell=True)


def refresh_https(filename):
    re_up_script = """
python << ACME_DIR >>/acme_tiny.py \
        --account-key ./account.key \
        --csr ./<< DOMAIN_NAME >>.csr \
        --acme-dir << HTTPSDIR >>/<< DOMAIN_NAME >>/.well-known/acme-challenge \
                > ./signed-<< DOMAIN_NAME >>.crt
cat signed-<< DOMAIN_NAME >>.crt lets-encrypt-r3-cross-signed.pem > chained-<< DOMAIN_NAME >>.pem
"""

    with open(filename, "r") as stream:
        config = yaml.safe_load(stream)
    configdir = os.path.dirname(os.path.realpath(filename))
    httpsdir = os.path.join(configdir, GENERATED, "https")

    x1 = os.path.abspath(__file__)
    x2 = os.path.dirname(x1)
    x3 = os.path.dirname(x2)
    acmedir = os.path.join(x3, "acme")

    if not os.path.exists(httpsdir):
        os.mkdir(httpsdir)
    os.chdir(httpsdir)

    for site, paths in grouped_sites(config):
        well_known = os.path.join(httpsdir, site, ".well-known", "acme-challenge")
        if not os.path.exists(well_known):
            os.makedirs(well_known)
        gkey = _templated(re_up_script, site, acme_dir=acmedir, httpsdir=httpsdir)
        subprocess.run(gkey, shell=True)

    print("Reloading nginx configuration files")
    subprocess.run("docker exec cleat-nginx-server nginx -s reload", shell=True)


def restart(service):
    os.system("service << >> stop")
    os.system("service << >> start")


class RunCommands:
    def __init__(self, runname):
        self.runname = runname

    def instance_container(self, url, siteconfig):
        name = "cleat-" + re.sub("[^a-zA-Z0-9]", "_", url)

        envs = []
        envconfig = siteconfig.get("environment", {})
        for k, v in envconfig.items():
            envs += ["-e", f"{k}={v}"]

        mounts = []
        mountmap = siteconfig.get("mounts", {})
        for k, v in mountmap.items():
            mounts += ["-v", f"{k}:{v}"]

        user = []
        usersc = siteconfig.get("user", "current")
        if usersc == "current":
            user = ["--user", str(os.getuid())]
        elif usersc != "root":
            user = ["--user", usersc]

        args = [
            "docker",
            "run",
            "--detach",
            "-l",
            self.runname,
            *envs,
            *mounts,
            *user,
            "--name",
            name,
            "--hostname",
            name,
            "--network",
            f"cleat_{self.runname}",
            siteconfig["image"],
        ]

        return args


def run_server(filename, dry_run=False):
    # run all the dockers in a non-ssl env for testing

    configdir = os.path.dirname(os.path.realpath(filename))

    with open(filename, "r") as stream:
        config = yaml.safe_load(stream)
    httpsdir = os.path.join(configdir, GENERATED, "https")
    confdir = os.path.join(configdir, GENERATED, "nginx", "conf.d")

    alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
    runname = "".join([random.choice(alpha) for x in range(8)])

    subnet = "172.20.0.0/16"

    args = [
        "docker",
        "network",
        "create",
        "--label",
        f"cleat.configfile={os.path.realpath(filename)}",
        "--subnet",
        subnet,
        f"cleat_{runname}",
    ]
    if dry_run:
        print(" ".join(args))
    else:
        subprocess.run(args)

    runc = RunCommands(runname)

    for url, siteconfig in config.items():
        # run a docker container for each backing server
        args = runc.instance_container(url, siteconfig)

        if dry_run:
            print(" ".join(args))
        else:
            subprocess.run(args)

    args = [
        "docker",
        "run",
        "--detach",
        "--name",
        "cleat-nginx-server",
        "-p",
        "80:80",
        "-p",
        "443:443",
        "--network",
        f"cleat_{runname}",
        "-l",
        runname,
        "-v",
        f"{httpsdir}:/etc/nginx/cleat",
        "-v",
        f"{confdir}:/etc/nginx/conf.d",
        "-v",
        f"{httpsdir}:/usr/share/nginx/",
        "nginx",
    ]

    if dry_run:
        print(" ".join(args))
    else:
        subprocess.run(args)

    print("services running:  stop with\n" f"cleat stop {runname}")


def _list_cleat_networks():
    cmd = [
        "docker",
        "network",
        "list",
        "--filter",
        "Name=cleat_*",
        "--format",
        "{{.Name}}",
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE)

    if proc.returncode:
        print("Error listing networks", file=sys.stderr)
        sys.exit(1)

    lines = proc.stdout.decode("utf-8").split("\n")
    networks = [ll for ll in lines if ll.strip() != ""]

    for network in networks:
        yield network[6:], network


def list_server():
    for runname, network in _list_cleat_networks():
        cmd = [
            "docker",
            "container",
            "list",
            "--filter",
            f"network={network}",
            "--format",
            "{{.ID}}",
        ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE)

        lines = proc.stdout.decode("utf-8").split("\n")
        print(f"Cleat network:  {runname}\n\t{len(lines)-1} containers")


def instance_restart(runname, urls, attached=False):
    if runname is None:
        networks = list(_list_cleat_networks())
        if len(networks) != 1:
            print("No network given to close.", file=sys.stderr)
            sys.exit(1)
        else:
            runname = networks[0][0]

    cmd = [
        "docker",
        "network",
        "inspect",
        f"cleat_{runname}",
    ]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE)
    network = json.loads(proc.stdout.decode("utf-8"))

    configfile = network[0]["Labels"].get("cleat.configfile", None)

    if not configfile or not os.path.exists(configfile):
        raise RuntimeError(f"Configuration directory {configfile} not found.")

    filename = configfile
    with open(filename, "r") as stream:
        config = yaml.safe_load(stream)

    runc = RunCommands(runname)

    for url, siteconfig in config.items():
        if url not in urls:
            continue

        name = "cleat-" + re.sub("[^a-zA-Z0-9]", "_", url)

        args = ["docker", "stop", name]
        subprocess.run(args)

        args = ["docker", "rm", name]
        subprocess.run(args)

        # run a docker container for each backing server
        args = runc.instance_container(url, siteconfig)
        if attached:
            args = [a for a in args if a != "--detach"]

        subprocess.run(args)


def stop_server(runname=None, unique_running=False):
    networks = list(_list_cleat_networks())
    if len(networks) == 1 and runname == None:
        prompt = f"A single cleat network {networks[0][0]} was found.\nWould you like to stop serving on this network now? [yn]  "
        if unique_running:
            answer = "y"
        else:
            answer = input(prompt)

        if answer.lower()[0] != "y":
            sys.exit(1)
        runname = networks[0][0]

    if runname == None:
        print("No network given to close.", file=sys.stderr)
        sys.exit(1)

    cmd = f'docker stop `docker ps --filter "label={runname}" -q `'
    # print(cmd)
    subprocess.run(cmd, shell=True)

    cmd = f'docker container rm `docker ps --all --filter "label={runname}" -q `'
    # print(cmd)
    subprocess.run(cmd, shell=True)

    args = ["docker", "network", "remove", f"cleat_{runname}"]
    # print(" ".join(args))
    subprocess.run(args)
