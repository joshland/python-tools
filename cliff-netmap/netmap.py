#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Python 3 Compat
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import sys
import yaml
import glob
import re
import logging
import colorsys
import random
logger = logging.getLogger(__name__)

import click
import click_log
import networkx as nx
from networkx.drawing.nx_agraph import graphviz_layout
import matplotlib.pyplot as plt

APP=os.path.basename(sys.argv[0])

LAYOUTS = [ 'spring', 'neato', 'fdp', 'sfdp', 'circo', 'twopi' ]
UNKNOWN = '#FFA500'

def graph(data, domains, node_scale, attractors, layout):
    private_subnets = re.compile(
        r'^((10)|(172\.1[6-9])|(172\.2[0-9])|(172\.3[0-1])|(192\.168))\.'
    )

    def short_name(fqdn):
        ''' splits fqdn into hostname, tld
        '''
        tld = '.'.join(fqdn.split('.')[-2:])
        shortname = re.sub('.' + tld, '', fqdn)
        return shortname, tld

    def get_colors(n):
        ''' n equidistant hues
        '''
        colors = []
        distance = 1.0 / n
        h, s, v = 0.5, 0.2, 0.7
        for i in range(n):
            colors.append("#%02x%02x%02x" % tuple([
                int(255 * c) for c in colorsys.hsv_to_rgb(h, s, v)
            ]))
            h += distance
        return colors

    def find_node(addr, tld):
        ''' locate a remote node
        '''
        for node in data:
            if addr in data[node]['local']:
                return node
        if private_subnets.match(addr):
            return None
        return tld if attractors else 'internet'

    def add_unknown_node(G, node, colors):
        ''' logic for handling undefined IP addresses
        '''
        if not node in G.node:
            if private_subnets.match(node):
                nodename, tld = node, None
            else:
                nodename, tld = short_name(node)
            color = colors.get(tld, UNKNOWN)
            G.add_node(node,
                size   = node_scale,
                color  = color,
                label  = nodename
            )
        else:
            G.node[node]['size'] += node_scale

    colors = dict(zip(domains, get_colors(len(domains))))

    G = nx.empty_graph()
    G.add_node('internet',
        size  = node_scale * 100,
        color = '#DFDFDF',
        label = 'Internet'
    )

    if attractors:
        for node in domains:
            G.add_node(node,
                size  = node_scale*100,
                color = colors[node],
                label = node
            )
            G.add_edge(node, 'internet',
                color  = colors.get(node, UNKNOWN),
                weight = 10 if attractors else 5,
                width  = 8 if attractors else 4
            )

    for node in data:
        shortname, tld = short_name(node)
        G.add_node(node,
            domain = tld,
            size   = node_scale * len(data[node]['remote']),
            color  = colors.get(tld, UNKNOWN),
            label  = shortname
        )

        if not data[node]['remote'] and attractors:
            # add a hidden edge, to force clustering
            G.add_edge(node, tld,
                color  = '#FFFFFF',
                weight = 1,
                width  = 0
            )
        for remote_addr in data[node]['remote']:
            other = find_node(remote_addr, tld)
            if not other: # unknown local host
                add_unknown_node(G, remote_addr, colors)
                G.add_edge(node, remote_addr,
                    color  = colors[tld],
                    weight = 2,
                    width  = 2
                )
                continue
            G.add_edge(node, other,
                color  = colors[tld],
                weight = 1,
                width  = 2
            )

    node_colors = []
    node_sizes = []
    node_labels = {}
    for node in G.nodes():
        node_colors.append(G.node[node]['color'])
        node_sizes.append(G.node[node]['size'])
        node_labels[node] = G.node[node]['label']

    edge_colors = []
    edge_widths = []
    for u, v in G.edges():
        edge_colors.append(G[u][v]['color'])
        edge_widths.append(G[u][v]['width'])

    if layout == 'spring':
        pos = nx.spring_layout(G,
            scale      = max(node_sizes),
            iterations = 500
        )
    else:
        pos = graphviz_layout(G, prog=layout)

    nx.draw(G, pos,
        node_color  = node_colors,
        node_size   = node_sizes,
        edge_color  = edge_colors,
        width       = edge_widths,
        node_shape  = 'o',
        with_labels = False,
        alpha       = 0.3,
        linewidths  = 0.5
    )

    nx.draw_networkx_labels(G, pos, node_labels,
        font_size   = 12,
        font_weight = 'bold'
    )

    plt.show()


@click.command()
@click.argument('datadir',                nargs=-1, required=True, type=click.Path(exists=True))
@click.option('--exclude-ports',    '-x', type=str, default='')
@click.option('--include-ports',    '-p', type=str, default='')
@click.option('--known-hosts',      '-k', type=click.File('rb'))
@click.option('--node-scale',       '-s', type=int, default=100)
@click.option('--layout',           '-l', type=click.Choice(LAYOUTS), default='fdp')
@click.option('--attractors',       '-a', is_flag=True, default=False)
@click.option('--output-yaml',            is_flag=True, default=False)
@click_log.simple_verbosity_option(default='WARN')
@click_log.init(__name__)
def main(datadir, exclude_ports, include_ports, known_hosts, node_scale, layout, attractors, output_yaml):
    '''Scans specified directories for files containing output of "netstat -tun",
    each named after the fqdn of the host it was collected from, and creates
    a (hopefully) pretty network graph of the result. Caveat: expects that IP
    addresses are unique, even for non-routable addresses across domains. There's
    no general solution for this that doesn't break more interesting features,
    such as cross-network link discovery (e.g VPN and proxies).

    Gathering netstat data is left as an exercise for the reader.

    \b
    Datadir layout
    ==============
    domain1.com/host1.domain1.com
                host2.domain1.com
                ...
    domain2.com/host1.domain2.com
                host2.domain2.com
                ...
    ...

    \b
    Known hosts
    ===========
    YAML file named "known-hosts.yaml", with a list of IP addresses per host,
    for example:
    ---
    gateway.domain1.com:
    - 192.168.0.1
    - 10.0.0.1
    ...

    This (optional) feature labels discovered hosts that lack a data file and so would
    otherwise show up as plain IP addresses.

    \b
    Example usage
    =============
    Map database connections across two domains:

    ./%(APP)s -p 5432,3306 path/to/domain1.com path/to/domain2.com -a

    Map ports up to 1024, except for ssh:

    ./%(APP)s -p 1-1024 -x 22 domain1.com

    ''' % locals()

    def parse_range(s):
        ''' convert string of the form 1,2,3-7,20 into list of integers
        '''
        result = set()
        if not s:
            return result
        for part in s.split(','):
            r = part.split('-')
            try:
                result.update(range(int(r[0]), int(r[-1]) + 1))
            except ValueError:
                logger.error("Invalid port specification: '{}'".format(part))
                raise SystemExit
        return result

    def parse_known_hosts(hostsfile):
        ''' hosts that would otherwise show up as IP addresses
        because they aren't present in data directory
        '''
        try:
            hosts = yaml.load(hostsfile)
        except:
            return {}
        return hosts if hosts else {}

    def find_refs(addresses, data):
        ''' search for hosts referencing these addresses
        '''
        refs = set()
        for host in data:
            for addr in data[host]['remote']:
                if addr in addresses:
                    refs.add(data[host]['local'][0])
        return refs

    exclude_ports = parse_range(exclude_ports)
    include_ports = parse_range(include_ports)
    known_hosts = parse_known_hosts(known_hosts)

    hostdata = {}

    for current_domain in datadir:
        for filename in glob.glob('{}/*'.format(current_domain)):
            hostname = os.path.basename(filename)
            hostdata[hostname] = {
                'local': set(),
                'remote': set()
            }

            regex = re.compile(
                r'^(tcp|udp)(4|6)?\s+\d+\s+\d+\s+'
                r'(?P<local_addr>\d+\.\d+\.\d+\.\d+):(?P<local_port>\d+)\s+'
                r'(?P<remote_addr>\d+\.\d+\.\d+\.\d+):(?P<remote_port>\d+)'
            )

            for line in open(filename).readlines():
                match = regex.search(line)
                if not match:
                    continue

                conn = { 'hostname': hostname }
                conn.update(match.groupdict())
                conn['local_port'] = int(conn['local_port'])
                conn['remote_port'] = int(conn['remote_port'])

                if conn['local_addr'].startswith('127.'):
                    continue

                hostdata[hostname]['local'].add(conn['local_addr'])

                if conn['local_addr'] == conn['remote_addr'] or conn['remote_addr'].startswith('127.'):
                    continue

                if exclude_ports and (conn['local_port'] in exclude_ports or conn['remote_port'] in exclude_ports):
                    logger.info("{hostname} rule exclude-ports removing {local_port} -> {remote_port}".format(**conn))
                    continue

                if include_ports and (conn['local_port'] not in include_ports and conn['remote_port'] not in include_ports):
                    logger.info("{hostname} rule include-ports removing {local_port} -> {remote_port}".format(**conn))
                    continue

                hostdata[hostname]['remote'].add(conn['remote_addr'])
                logger.info("{hostname} adding {local_addr}:{local_port} -> {remote_addr}:{remote_port}".format(**conn))

            hostdata[hostname]['local'] = list(hostdata[hostname]['local'])
            hostdata[hostname]['remote'] = list(hostdata[hostname]['remote'])

    for host in known_hosts:
        hostdata.setdefault(host, { 'local': set(), 'remote': set() })
        hostdata[host]['local'].update(known_hosts[host])
        hostdata[host]['remote'].update(find_refs(hostdata[host]['local'], hostdata))

    if output_yaml:
        print(yaml.safe_dump(hostdata, default_flow_style=False))

    domains = [ d.strip('/').split('/')[-1] for d in datadir ]
    graph(hostdata, domains, node_scale, attractors, layout)


if __name__ == '__main__':
    main()
