#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse

from wsgiref.simple_server import make_server
from tg import MinimalApplicationConfigurator

from api_client import setup_logging
from controller import HermineController


def main():
    parser = argparse.ArgumentParser(description="Start")
    parser.add_argument("host", type=str, nargs='?', default="localhost")
    parser.add_argument("port", type=int, nargs='?', default=8080)
    parser.add_argument("--debug", action="store_true", default=False)
    args = parser.parse_args()

    setup_logging(args.debug)

    config = MinimalApplicationConfigurator()
    config.update_blueprint({"root_controller": HermineController()})
    print("Serving on {}:{}".format(args.host, args.port))
    httpd = make_server(args.host, args.port, config.make_wsgi_app())
    httpd.serve_forever()


if __name__ == "__main__":
    main()
