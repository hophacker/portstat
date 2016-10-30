#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import time
import argparse
import requests

try:
    from urllib.parse import urlencode
except ImportError:
    from urllib import urlencode

try:
    import urllib.request as urllib2
except ImportError:
    import urllib2

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

__author__ = 'imlonghao'
__version__ = '0.0.6'


def version():
    return __version__.split(',')


def getConfig(path):
    settings = configparser.ConfigParser()
    settings.read(path)
    portGroups = []
    for each in settings.sections():
        portGroups.append(
            [each, settings.get(each, 'Port'), settings.get(each, 'Webhook')])
    return portGroups


def sync(portGroups):
    with open('/etc/portstat.rules', 'w') as portstat_rules:
        portstat_rules.write('#!/bin/bash\n')
        portstat_rules.write('/sbin/iptables -F PORTSTAT\n')
        for each in portGroups:
            if '-' in each[1]:
                begin = int(each[1].split('-')[0])
                end = int(each[1].split('-')[1]) + 1
                for i in range(begin, end):
                    portstat_rules.write(
                        '/sbin/iptables -A PORTSTAT -p tcp --dport %s\n'
                        % str(i))
                    portstat_rules.write(
                        '/sbin/iptables -A PORTSTAT -p tcp --sport %s\n'
                        % str(i))
            elif ',' in each[1]:
                portLists = each[1].split(',')
                while '' in portLists:
                    portLists.remove('')
                for i in portLists:
                    portstat_rules.write(
                        '/sbin/iptables -A PORTSTAT -p tcp --dport %s\n' % i)
                    portstat_rules.write(
                        '/sbin/iptables -A PORTSTAT -p tcp --sport %s\n' % i)
            else:
                portstat_rules.write(
                    '/sbin/iptables -A PORTSTAT -p tcp --dport %s\n' % each[1])
                portstat_rules.write(
                    '/sbin/iptables -A PORTSTAT -p tcp --sport %s\n' % each[1])
    os.system('/bin/bash /etc/portstat.rules')


def flushDrop():
    os.system('/sbin/iptables -F DROP_PORTS')


def upload(portGroups):
    # stats = {9999: 11111}, {10000: 11112}
    stats = {}
    for each in os.popen('/sbin/iptables -vxn -L PORTSTAT').readlines()[2:]:
        cols = each.strip().split()
        port = int(cols[9][4:])
        value = int(cols[1])
        if port in stats:
            stats[port] += value
        else:
            stats[port] = value
    # datas = [{'1.php': {22: 100}}, {'2.php': {21: 101, 22: 99}}]
    datas = []
    for each in portGroups:
        line = {}
        if '-' in each[1]:
            begin = int(each[1].split('-')[0])
            end = int(each[1].split('-')[1]) + 1
            for i in range(begin, end):
                line[i] = stats[i]
        elif ',' in each[1]:
            portLists = each[1].split(',')
            while '' in portLists:
                portLists.remove('')
            for i in portLists:
                line[int(i)] = stats[int(i)]
        else:
            line[int(each[1])] = stats[int(each[1])]
        datas.append({each[2]: line})
    for each in datas:
        ret = requests.post('%s&time=%s' % (each.keys()[0], str(int(time.time()))),
                      json={
                          'portstat': each.values()[0]
                      }).json()
        flushDrop()
        for port in ret['drop_ports']:
            os.system('/sbin/iptables -A DROP_PORTS -p tcp --dport %s -j DROP' % port)
    os.system('/sbin/iptables -Z PORTSTAT')


def main():
    parser = argparse.ArgumentParser(
        description='A simple port traffic monitor')
    parser.add_argument('-c', '--config', type=str,
                        default='/etc/portstat.conf',
                        help='Path of the config file.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        '-v', '--version', help='Show portstat version.', action='store_true')
    group.add_argument(
        '-s', '--sync',
        help='Sync the portstat settings and iptables.', action='store_true')
    group.add_argument(
        '-u', '--upload',
        help='Upload the port stat with webhook.', action='store_true')
    group.add_argument(
        '-f', '--flush-drop',
        help='Flush ports dropped in DROP group.', action='store_true')
    args = parser.parse_args()
    portGroups = getConfig(args.config)
    if args.version:
        print('portstat in version %s' % version())
    if args.sync:
        sync(portGroups)
    if args.upload:
        upload(portGroups)
    if args.flush_drop:
        flushDrop()


if __name__ == '__main__':
    main()
