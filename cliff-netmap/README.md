Netmap
======

This turns the output of multiple systems into a connection graph.  It can be used in general, or to target specific types of links.

    netstat -tun


Grab that output, and put into a data directory under a domain folder:

    .
    ├── dom2.net
    │   ├── app1.dom2.net
    │   ├── bastion.dom2.net
    │   └── web1.dom2.net
    ├── mycom.org
    │   ├── app1.mycom.org
    │   ├── bastion.mycom.org
    │   └── web1.mycom.org
    └── mydom.com
        ├── app1.mydom.com
        ├── bastion.mydom.com
        └── web1.mydom.com


FTC
===

    Scans specified directories for files containing output of "netstat -tun",
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


Links
-----

Cliff Wells  - https://github.com/cwells

Gist Link -  https://gist.github.com/cwells/ad0870a30ce3357a9a8a6970b48db8a6


Quick Configuration
-------------------

Works with Python2 or Python3

    pip install -r requirements.txt


