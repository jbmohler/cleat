import os
import argparse
from . import core
from . import vault


def main():
    parser = argparse.ArgumentParser(
        description="cleat: Take your docker containers to https in 60 seconds or less."
    )
    subparsers = parser.add_subparsers(dest="operation")

    setup = subparsers.add_parser(
        "setup", help="prepare configuration directory and SSL keys"
    )
    setup.add_argument("-f", "--file", required=True, help="configuration yaml file")

    run = subparsers.add_parser("run", help="run the server")
    run.add_argument("-f", "--file", required=True, help="configuration yaml file")
    run.add_argument(
        "-d",
        "--dry_run",
        required=False,
        default=False,
        action="store_true",
        help="print docker commands to start server rather than execute them",
    )
    # run.add_argument("-d", "--dir", required=True, help="configuration directory")

    stop = subparsers.add_parser("stop", help="stop the server")
    stop.add_argument("runname", nargs="?", help="the runname to stop")
    stop.add_argument(
        "-u",
        "--unique-running",
        required=False,
        default=False,
        action="store_true",
        help="stop the single running cleat instance with no confirmation (otherwise ask)",
    )

    subparsers.add_parser("list", help="list running cleat instances by docker network")

    instance_restart = subparsers.add_parser(
        "instance-restart", help="restart a specific instance specified by url"
    )
    instance_restart.add_argument(
        "instance_urls",
        metavar="instance-urls",
        nargs="+",
        help="url indicating instance to restart",
    )
    instance_restart.add_argument(
        "runname", nargs="?", help="the runname of instances to restart"
    )

    ssl_update = subparsers.add_parser("update-ssl", help="refresh the https from acme")
    ssl_update.add_argument(
        "-f", "--file", required=True, help="configuration yaml file"
    )

    args = parser.parse_args()

    if args.operation == None:
        parser.print_help()
    elif args.operation == "setup":
        core.generate_configuration(args.file, ssl=True, plain=False)
        core.generate_configuration_acme(args.file)
        core.initialize_https(args.file)
    elif args.operation == "run":
        core.run_server(args.file, args.dry_run)
    elif args.operation == "stop":
        core.stop_server(args.runname, unique_running=args.unique_running)
    elif args.operation == "instance-restart":
        core.instance_restart(urls=args.instance_urls, runname=args.runname)
    elif args.operation == "list":
        core.list_server()
    elif args.operation == "update-ssl":
        core.refresh_https(args.file)


def vault_main():
    parser = argparse.ArgumentParser(
        description="cleat-vault: manage cleat secret vaults"
    )
    subparsers = parser.add_subparsers(dest="operation")

    setup = subparsers.add_parser("init", help="initialize a secret vault")
    setup.add_argument("-f", "--file", required=True, help="configuration yaml file")

    run = subparsers.add_parser("dump", help="print all the secrets in plain text")
    run.add_argument("-f", "--file", required=True, help="configuration yaml file")

    args = parser.parse_args()

    if args.operation == None:
        parser.print_help()
    elif args.operation == "init":
        with vault.pw_fernet() as f:
            clvault = os.path.expanduser("~/.cleat/vault")
            obj = {"pgpass": "oihro3i", "pgurl": "postgresql://jbmohler:laksjdf/mydb"}
            vault.write_encrypted_content(f, clvault, obj)
    elif args.operation == "dump":
        with vault.pw_fernet() as f:
            clvault = os.path.expanduser("~/.cleat/vault")
            obj = vault.read_encrypted_content(f, clvault)
            print(obj)
