import argparse
import importlib
import logging
import os
import sys

def main(args=None):
    scriptName = os.path.basename(__file__)
    parser = argparse.ArgumentParser(scriptName)
    levels = ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
    parser.add_argument('--log-level', default='INFO', choices='levels')
    subparsers = parser.add_subparsers(dest='command', help='Available Commands:')

    start_cmd = subparsers.add_parser('start', help='Start a service')
    start_cmd.add_argument('name', metavar='NAME', help='Name of service to start')

    stop_cmd = subparsers.add_parser('stop', help='Stop a service')
    stop_cmd.add_argument('names', metavar='NAME', help='Name of service to start')


