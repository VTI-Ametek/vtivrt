#!/bin/python
from src.vtivrt import VtiVrtReader

import argparse
parser = argparse.ArgumentParser('Read and print VRT packets')
parser.add_argument('hostname', type=str, action='store')
parser.add_argument('--port', type=int, default=9901, action='store')
parser.add_argument('--point', type=int, default=None, action='store')
args = parser.parse_args()
r = VtiVrtReader(args.hostname, args.port, args.point)
while True:
    try:
        print(r.read(True))
    except KeyboardInterrupt:
        print('******** aborted ********')
        break
