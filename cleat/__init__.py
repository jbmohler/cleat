import os
import argparse
from . import core


def main():
    parser = argparse.ArgumentParser(description="cleat: from docker to https")
    subparsers = parser.add_subparsers(dest="operation")

    setup = subparsers.add_parser(
        "setup", help="prepare configuration directory and SSL keys"
    )
    setup.add_argument("-f", "--file", required=True, help="configuration yaml file")

    run = subparsers.add_parser("run", help="run the server")
    run.add_argument("-f", "--file", required=True, help="configuration yaml file")
    # run.add_argument("-d", "--dir", required=True, help="configuration directory")

    stop = subparsers.add_parser("stop", help="stop the server")
    stop.add_argument("runname", help="the runname to stop")

    ssl_update = subparsers.add_parser("ssl-update", help="refresh the https from acme")
    ssl_update.add_argument(
        "-f", "--file", required=True, help="configuration yaml file"
    )

    args = parser.parse_args()

    if args.operation == None:
        parser.print_help()
    elif args.operation == "setup":
        configdir = os.path.dirname(os.path.realpath(args.file))
        core.generate_configuration(args.file, ssl=False, plain=True)
        core.generate_configuration_acme(args.file)
        core.initialize_https(configdir)
    elif args.operation == "run":
        core.run_server(args.file)
    elif args.operation == "stop":
        core.stop_server(args.runname)
    elif args.operation == "ssl-update":
        core.refresh_https()
