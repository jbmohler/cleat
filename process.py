import argparse


TEMPLATE_SITES_AVAILABLE = """
server {
    listen 443;
    server_name << DOMAIN_NAME >>;
    add_header Strict-Transport-Security max-age=31536000;

    ssl on;
    ssl_certificate << DOMAIN_PEM >>;
    ssl_certificate_key << DOMAIN_KEY >>;
    ssl_session_timeout 5m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA256";      
    ssl_session_cache shared:SSL:50m;
    ssl_dhparam myssldir/dhparam4096.pem;
    ssl_prefer_server_ciphers on;

    location /.well-known/ {
        root << UNKNOWN_ROOT >>/<< DOMAIN_NAME >>/.well-known/;
    }

    location / {
        proxy_set_header    Host $host;
        proxy_set_header    X-Real-IP $remote_addr;
        proxy_set_header    X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header    X-Forwarded-Proto $scheme;

        proxy_pass          http://localhost:<< PORT >>;
        proxy_read_timeout  90;
    }
}
"""

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


def generate_sites_available():
    pass

def generate_systemd_services():

    pass

def initialize_https():
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


if __name__ == '__main__':
    pass
