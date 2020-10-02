import argparse
import importlib
import logging
import os
import sys


def main(args=None):
    scriptname = os.path.basename(__file__)
    parser = argparse.ArgumentParser(scriptname)
    levels = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
    parser.add_argument('--log-level', default='INFO', choices=levels)
    subparsers = parser.add_subparsers(dest='command', help='Available commands:')

    start_cmd = subparsers.add_parser('start', help='Start a service')
    start_cmd.add_argument('name', metavar='NAME', help='Name of service to start')

    stop_cmd = subparsers.add_parser('stop', help='Stop one or more services')
    stop_cmd.add_argument('name', metavar='NAME', help='Name of service to stop')

    restart_cmd = subparsers.add_parser('restart', help='Restart one or more services')
    restart_cmd.add_argument('names', metavar='NAME', nargs='+', help='Restart one or more services.')

    options = parser.parse_args()

    # the code to dispatch commands could all be in this file. For the purposes
    # of illustration only, we implement each command in a separate module.
    try:
        mod = importlib.import_module(options.command)
        cmd = getattr(mod, 'command')
    except (ImportError, AttributeError):
        print('Unable to find the code for command \'%s\'' % options.command)
        return 1

    # Could get fanoy here and load conifguration from file or dictionary
    logging.basicConfig(level=options.log_level, format='%(levelname)s %(name)s %(message)s')

    cmd(options)


if __name__ == '__main__':
    sys.exit(main())
