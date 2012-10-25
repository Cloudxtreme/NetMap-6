#!/usr/bin/env python
"""
A simple tool to scan networks and create a nice graph of it.

Self notes:
-----------
Local address: socket.gethostbyname(socket.gethostname())
http://code.google.com/p/netaddr/wiki/IPTutorial
https://github.com/leonidg/Poor-Man-s-traceroute

FIXME
-----
Get threading working
"""

import sys
import socket
import netifaces
from netaddr import IPNetwork
from netaddr.core import AddrFormatError
from threading import Thread
from Queue import Queue


MAX_WORKERS = 1


class Netmap():

    def __init__(self):
        self.networks = []
        self.taskqueue = Queue()
        self.workers = []
        self.hosts = {}
        self.local_addresses = self.localAddresses()

    def localAddresses(self):
        result = []
        for i in netifaces.interfaces():
            addr = netifaces.ifaddresses(i)
            if 2 in addr:
                result.append(addr[2][0]['addr'])
        return result

    def addNetwork(self, network):
        try:
            net = IPNetwork(network)
            self.networks.append(net)
        except AddrFormatError:
            print >> sys.stderr, "Invalid network address %s" % network
        except Exception:
            print >> sys.stderr, "Error parsing network address %s" % network

    def scan(self):
        # build up queue
        for network in self.networks:
            for ip in network.iter_hosts():
                self.taskqueue.put((self.addIfAlive, str(ip), network))
        # launching workers
        for i in range(MAX_WORKERS):
            w = Thread(target=self.worker)
            w.daemon = True
            self.workers.append(w)
            w.start()
        # wait until taskqueue is processed
        self.taskqueue.join()

    def worker(self):
        while True:
            task = self.taskqueue.get()
            task[0](task[1], task[2])
            self.taskqueue.task_done()

    def addIfAlive(self, ip, network):
        #print "Ping %s" % ip
        if self.icmp(ip) is not None:
            if ip not in self.hosts:
                self.hosts[ip] = {'net': network, 'next': []}
                self.taskqueue.put((self.addTraced, ip, network))

    def addTraced(self, ip, network):
        #print "Trace %s" % ip
        trace = self.trace(ip)
        for hop, nexthop in zip(trace[::1], trace[1::1]):
            if hop not in self.hosts:
                self.hosts[hop] = {'next': []}
            if nexthop not in self.hosts:
                self.hosts[nexthop] = {'next': []}
            if nexthop not in self.hosts[hop]['next']:
                self.hosts[hop]['next'].append(nexthop)

    def icmp(self, ip, ttl=30):
        icmp = socket.getprotobyname('icmp')
        udp = socket.getprotobyname('udp')
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        recv_sock.settimeout(0.2)
        recv_sock.bind(('', 0))
        send_sock.sendto('', (ip, 1))  # port 1 is fine. doen't matter with icmp?
        addr = None
        try:
            _, addr = recv_sock.recvfrom(512)
            addr = addr[0]
        except socket.error:
            pass
        finally:
            send_sock.close()
            recv_sock.close()
        if ip in self.local_addresses or addr not in self.local_addresses:
            return addr
        else:
            return None

    def trace(self, ip):
        result = []
        hop = None
        ttl = 1
        while hop != ip and ttl <= 30:
            hop = self.icmp(ip, ttl)
            if hop is not None:
                result.append(hop)
            ttl += 1
        return result

    def printDot(self):
        print "graph G {"
        print "node [shape=ellipse];"
        for net in self.networks:
            print "\"%s\";" % net
        print "node [shape=box];"
        for host in self.hosts:
            if 'net' in self.hosts[host]:
                print "\"%s\" -- \"%s\";" % (self.hosts[host]['net'], host)
            if 'next' in self.hosts[host]:
                for nexthop in self.hosts[host]['next']:
                    print "\"%s\" -- \"%s\";" % (host, nexthop)
        print "}"

if __name__ == '__main__':
    app = Netmap()
    for arg in sys.argv[1:]:
        app.addNetwork(arg)
    app.scan()
    app.printDot()
