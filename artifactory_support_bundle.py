#!/usr/bin/env python
"""
Python script using ``requests`` to generate, list, and download JFrog
Artifactory support bundles via the ReST API, from one or more instances/nodes.

Tested against JFrog Artifactory Enterprise 4.16.1 (HA Cluster).

Should work with python 3.4+. Requires ``requests`` from pypi.

The latest version of this script can be found at:
http://github.com/jantman/misc-scripts/blob/master/artifactory_support_bundle.py

Copyright 2018 Jason Antman <jason@jasonantman.com> <http://www.jasonantman.com>
Free for any use provided that patches are submitted back to me.

CHANGELOG (be sure to increment VERSION):

v0.1.0 2018-04-05 Jason Antman <jason@jasonantman.com>:
  - initial version of script
v0.1.1 2021-12-22 Matthaeus Krahulec <matthaeus.krahulec@bearingpoint.com>:
  - Adapt script for Artifactory 7.27.3
"""

import os
import sys
import argparse
import logging
from json.decoder import JSONDecodeError
from urllib.parse import urlparse
from time import time
from datetime import datetime, timedelta

try:
    import requests
except ImportError:
    sys.stderr.write(
        'ERROR: this script requires the python "requests" package. Please '
        'install it with "pip install requests"'
    )
    raise SystemExit(1)

VERSION = '0.1.1'
PROJECT_URL = 'https://github.com/jantman/misc-scripts/blob/master/' \
              'artifactory_support_bundle.py'

FORMAT = "[%(asctime)s %(levelname)s] %(message)s"
logging.basicConfig(level=logging.WARNING, format=FORMAT)
logger = logging.getLogger()


class ArtifactorySupportBundles(object):
    """Class to manage JFrog Artifactory support bundles via ReST API"""

    def __init__(self, username, password, bundle_name,jfrog , urls):
        self._username = username
        self._password = password
        self.urls = []
        for u in urls:
            if u.endswith('/'):
                self.urls.append(u)
            else:
                self.urls.append(u + '/')
        logger.debug('Artifactory URLs: %s', urls)
        self._requests = requests.Session()
        self._requests.auth = (self._username, self._password)
        self._bundle_name = bundle_name
        self._jfrog = jfrog

    def run(self, action):
        """ do stuff here """
        logger.debug('Running action: %s', action)
        if action == 'list-bundles':
            return self.list_bundles()
        if action == 'get-latest-bundle':
            return self.get_latest_bundle()
        if action == 'create-bundle':
            return self.create_bundle()
        if action == 'bundle2jfrog':
            return self.bundle2jfrog()
        raise RuntimeError('Unknown action: %s' % action)

    def _list_bundles(self, art_url):
        url = '%sapi/system/support/bundles/' % art_url
        logger.debug('GET %s', url)
        res = self._requests.get(url)
        #print(res)
        logger.debug(
            '%s responded %s %s with %d bytes', url, res.status_code,
            res.reason, len(res.content)
        )
        if len(res.content) == 0:
            logger.info('%s returned empty response; assuming no bundles', url)
            return []
        try:
            val = res.json()['bundles']
        except JSONDecodeError:
            logger.error('Error decoding response as JSON: %s', res.text)
            raise
        return val

    def list_bundles(self):
        for url in self.urls:
            print('=> %s' % url)
            res = self._list_bundles(url)
            #print(res)
            if len(res) == 0:
                print('(no bundles)')
                continue
            idict = {'id': 'ccsd234234-1631529354430', 'name': 'ccsd234234', 'description': '', 'created': '2021-09-13T10:35:54Z', 'status': 'success'} # initial entry to search for newer timestamps
            bids = list()
            for b in res:
                print(b)
                idict = {k:v for (k,v) in b.items()}
                if self._bundle_name == None:
                    print('Searching for the latest bundle because no name was defined')
                    created = idict.get('created')
                    timestamp = datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ")
                    if idict.get('created') == self._bundle_name: # TODO search for the latest bundle
                        bids.append(idict.get('id', 'NotFound'))
                else:
                    if idict.get('name') == self._bundle_name:
                        bids.append(idict.get('id', 'NotFound')) #list ids for bundle name
            logger.debug('Selected bundle ids %s', bids)
        return bids


    def _get_bundle(self, url, bundle_path):
        p = urlparse(url)
        #fname = '%s_%s' % (p.hostname, bundle_path)
        logger.debug('GET %s to: %s', url, bundle_path)
        res = self._requests.get(url, stream=True)
        logger.debug(
            '%s responded %s %s; streaming to disk at %s', url, res.status_code,
            res.reason, bundle_path
        )
        res.raise_for_status()
        size = 0
        with open(bundle_path, 'wb') as fh:
            for chunk in res.iter_content(chunk_size=1024):
                fh.write(chunk)
                size += len(chunk)
        logger.info('Downloaded %d bytes to: %s', size, bundle_path)
        return bundle_path

    def get_latest_bundle(self):
        success = True
        if not os.path.exists('bundles'):
            os.mkdir('bundles')
        for url in self.urls:
            bids = self.list_bundles() #use bundle IDs for download
            logger.debug('Bundles for %s: %s', url, bids)
            if len(bids) < 1:
                logger.warning('No bundles found for %s; skipping', url)
                continue
            # bids should already contain the latest bundle
            paths = list()
            for id in bids: # Artifactory 7 splits large bundles into several bundle ids
                logger.debug('Filename for latest bundle: %s', id)
                bundle_url = '%sapi/system/support/bundle/%s/archive' % (url, id)
                bundle_path = 'bundles/%s' % (id)
                try:
                    paths.append(self._get_bundle(bundle_url, bundle_path)) #list of paths
                    print('Downloaded %s to: %s' % (bundle_url, bundle_path))
                except Exception:
                    logger.error(
                        'Exception downloading %s', bundle_url, exc_info=True
                    )
                    success = False
            if not success:
                logger.error('Some downloads failed.')
                raise SystemExit(1)
        return paths

    def _create_bundle(self, art_url):
        today = datetime.now()
        day_before = today - timedelta(1)
        """
        see: https://www.jfrog.com/confluence/display/JFROG/Artifactory+REST+API
        """
        data = {
            "name": self._bundle_name,
            "description": "test",
            "parameters":{
                "logs":{
                    "start_date": day_before.strftime("%y-%m-%d"),
                    "end_date": today.strftime("%y-%m-%d")
                },
                "thread_dump":{
                    "include": "false", #false because this might cause Upload/Download failures during bundle creation
                    "count": 0, 
                    "interval": 0
                }
            }
        }
        url = '%sapi/system/support/bundle/' % art_url
        logger.debug('POST to %s: %s', url, data)
        print('Triggering creation of bundle on %s...' % art_url)
        start = time()
        res = self._requests.post(url, json=data)
        duration = time() - start
        logger.debug(
            '%s responded %s %s in %s seconds with %d bytes', url,
            res.status_code, res.reason, duration, len(res.content)
        )
        res.raise_for_status()
        print('\tBundle creation complete in %s seconds' % duration)
        # commented the following section becaue it threw an error even though the bundle was successfully created
        # try:
        #     val = res.json()['bundle'][0]
        # except JSONDecodeError:
        #     logger.error('Error decoding response as JSON: %s', res.text)
        #     raise
        # return val

    def create_bundle(self):
        success = True
        for url in self.urls:
            print('=> %s' % url)
            try:
                res = self._create_bundle(url)
                print('Created bundle "%s" on %s' % (self._bundle_name, url))
            except Exception:
                logger.error(
                    'Exception creating bundle on %s', url, exc_info=True
                )
                success = False
        if not success:
            logger.error('Some bundle creations failed.')
            raise SystemExit(1)

    def _upload_bundle(self,fpath):
        print('curl -i -T %s "https://supportlogs.jfrog.com/logs/%s/' % (fpath, self._jfrog))
    def bundle2jfrog(self):
        success = True
        for url in self.urls:
            print('=> %s' % url)
            try:
                res = self._create_bundle(url)
                print('Created bundle "%s" on %s' % (self._bundle_name, url))
            except Exception:
                logger.error(
                    'Exception creating bundle on %s', url, exc_info=True
                )
                success = False
        if not success:
            logger.error('Some bundle creations failed.')
            raise SystemExit(1)
        try:
            paths = self.get_latest_bundle
            print('Downloaded bundles "%s" from %s' % (paths, url))
        except Exception:
            logger.error(
                'Exception downloading bundle on %s', url, exc_info=True
            )
            success = False
        if not success:
            logger.error('Bundle download failed.')
            raise SystemExit(1)
        for p in paths:
            try:
                res = self._upload_bundle(p)
                print('Uploaded bundle "%s" to Jfrog ticket %s' % (p, self._jfrog ))
            except Exception:
                logger.error(
                    'Exception uploading bundle on %s', url, exc_info=True
                )
                success = False
            if not success:
                logger.error('Bundle upload failed.')
                raise SystemExit(1)

def parse_args(argv):
    """
    parse arguments/options

    this uses the new argparse module instead of optparse
    see: <https://docs.python.org/2/library/argparse.html>
    """
    p = argparse.ArgumentParser(
        description='manage JFrog Artifactory support bundles via ReST API',
        prog='artifactory_support_bundle.py',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='ACTIONS:\n'
               '  list-bundles      - list all support bundles on specified '
               'instances.\n'
               '  get-latest-bundle - download the latest support bundle'
               'from each instance.\n'
               '  create-bundle     - trigger creation of a new support bundle '
               'with all data/options and 7 days of logs, on each instance.'
    )
    p.add_argument('-v', '--verbose', dest='verbose', action='count', default=0,
                   help='verbose output. specify twice for debug-level output.')
    p.add_argument(
        '-V', '--version', action='version',
        version='%(prog)s ' + '%s <%s>' % (VERSION, PROJECT_URL)
    )
    p.add_argument(
        '-u', '--username', action='store', dest='username', default=None,
        help='Artifactory username. Can also be specified via ARTIFACTORY_USER '
             'environment variable (argument overrides environment variable).',
        type=str
    )
    p.add_argument(
        '-p', '--password', action='store', dest='password', default=None,
        help='Artifactory password. Can also be specified via ARTIFACTORY_PASS '
             'environment variable (argument overrides environment variable). '
             'An Artifactory API key can also be used as a password with '
             'Artifactory >= 4.4.3.',
        type=str
    )
    p.add_argument(
        '-b', '--bundle_name', action='store', dest='bundle_name', default=None,  #TODO
        help='Support Bundle Name please do not use special characters'
             'The default is date and time',
        type=str
    )
    p.add_argument(
        '-j', '--jfrog_ticket', action='store', dest='jfrog', default=None,  #TODO
        help='JFrog ticket number where the support bundle should get uploaded',
        type=str
    )
    actions = ['list-bundles', 'get-latest-bundle', 'create-bundle', 'bundle2jfrog']
    p.add_argument(
        'ACTION', action='store', choices=actions,
        help='action to perform; see below for details'
    )
    p.add_argument(
        'ARTIFACTORY_URL', type=str, nargs='+',
        help='URL(s) to one or more Artifactory instances to run actions '
             'against; form should be "http(s)://server(:port)?/artifactory/"'
    )
    args = p.parse_args(argv)
    for argname, varname in {
        'username': 'ARTIFACTORY_USER',
        'password': 'ARTIFACTORY_PASS'
    }.items():
        if getattr(args, argname) is None:
            e = os.environ.get(varname, None)
            if e is None:
                raise RuntimeError(
                    'ERROR: you must specify either the %s option or the '
                    '%s environment variable.' % (argname, varname)
                )
            setattr(args, argname, e)
    return args


def set_log_info():
    """set logger level to INFO"""
    set_log_level_format(logging.INFO,
                         '%(asctime)s %(levelname)s:%(name)s:%(message)s')


def set_log_debug():
    """set logger level to DEBUG, and debug-level output format"""
    set_log_level_format(
        logging.DEBUG,
        "%(asctime)s [%(levelname)s %(filename)s:%(lineno)s - "
        "%(name)s.%(funcName)s() ] %(message)s"
    )


def set_log_level_format(level, format):
    """
    Set logger level and format.

    :param level: logging level; see the :py:mod:`logging` constants.
    :type level: int
    :param format: logging formatter format string
    :type format: str
    """
    formatter = logging.Formatter(fmt=format)
    logger.handlers[0].setFormatter(formatter)
    logger.setLevel(level)


if __name__ == "__main__":
    args = parse_args(sys.argv[1:])

    # set logging level
    if args.verbose > 1:
        set_log_debug()
    elif args.verbose == 1:
        set_log_info()

    script = ArtifactorySupportBundles(
        args.username, args.password, args.bundle_name, args.jfrog, args.ARTIFACTORY_URL
    )
    script.run(args.ACTION)
