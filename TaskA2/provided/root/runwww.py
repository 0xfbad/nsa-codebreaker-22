#!/usr/bin/env python3

# This script will create an anonymous, secure, temporary web server to transfer files over HTTPS.

import argparse
import datetime
import os
import random
import string
import subprocess
import sys

try:
    import libfaketime
except ImportError:
    subprocess.run(f'{sys.executable} -m pip install --user libfaketime', shell=True)
    import libfaketime


p = argparse.ArgumentParser()
p.add_argument('port', type=int)
args = p.parse_args()

certfile = '.cert.pem'
randoff = datetime.timedelta(seconds=random.randrange(3 * 365 * 24 * 3600))
dt = datetime.datetime.strptime('2017-01-01 00:00:00', '%Y-%m-%d %H:%M:%S') + randoff
env = libfaketime.get_reload_information()[1]
env['FAKETIME'] = dt.strftime('%Y-%m-%d %H:%M:%S')
cn = ''.join(c for c in random.choices(string.ascii_lowercase, k=12))
subprocess.run(
    f'openssl req -x509 -out {certfile} -new -keyout {certfile} -newkey rsa:4096 -batch -nodes -subj /CN={cn} -days 3650',
    env=env,
    stderr=subprocess.DEVNULL,
    check=True,
    shell=True)
subprocess.run(f'openssl x509 -noout -text -in {certfile}', shell=True)
print(f'Running openssl HTTPS server on port {args.port}')
os.execlp('openssl', 'openssl', 's_server', '-accept', str(args.port), '-cert', certfile, '-tls1_2', '-cipher', 'AES256-GCM-SHA384', '-WWW')
