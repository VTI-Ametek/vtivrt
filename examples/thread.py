#!/bin/python
import time
from pprint import pprint
from src.vtivrt import VtiVrtThread

import argparse
parser = argparse.ArgumentParser('Read and print VRT packets')
parser.add_argument('hosts', type=str, action='store', nargs='+')
args = parser.parse_args()

hosts = []
for host in args.hosts:
    parts = host.split(':')
    vals = [parts[0]]
    for part in parts[1:]:
        vals.append(int(part))
    hosts.append(vals)
t = VtiVrtThread(hosts)
t.start()
while True:
    try:
        packets = t.read(1, block=True)
        if packets:
            for ch, packs in packets.items():
                print(ch)
                pprint(packs)
        else:
            time.sleep(1)
    except KeyboardInterrupt:
        print('******** aborted ********')
        t.stop()
        t.join()
        break
    except TimeoutError:
        t.stop()
        t.join()
        raise
