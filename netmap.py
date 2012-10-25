#!/usr/bin/env python
"""
A simple tool to scan networks and create a nice graph of it.

Self notes:
-----------
Local address: socket.gethostbyname(socket.gethostname())
http://code.google.com/p/netaddr/wiki/IPTutorial
https://github.com/leonidg/Poor-Man-s-traceroute
"""

import sys
from netaddr import IPNetwork
from netaddr.core import AddrFormatError
from threading import Thread
from Queue import Queue


num_threads = 1


class Netmap():

    def __init__(self):
        self.networks = []
        self.taskqueue = Queue()
        self.workers = []
        self.hosts = []

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
                self.taskqueue.put((self.isAlive, str(ip)))
        # launching workers
        for i in range(num_threads):
            w = Thread(target=self.worker)
            w.daemon = True
            self.workers.append(w)
            w.start()
        # wait until taskqueue is processed
        self.taskqueue.join()

    def worker(self):
        # while not self.taskqueue.empty():
        while True:
            task = self.taskqueue.get()
            task[0](task[1])
            self.taskqueue.task_done()

    def getDot(self):
        pass

    def isAlive(self, ip):
        print ip


class Traceroute():
    pass


if __name__ == '__main__':
    app = Netmap()
    for arg in sys.argv[1:]:
        app.addNetwork(arg)
    app.scan()
    print app.getDot()
