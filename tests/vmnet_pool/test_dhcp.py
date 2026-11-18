#!/usr/bin/env python3
"""Repeatedly boot an existing DHCP-enabled .hvt and check real lease reuse.

python3 tests/vmnet_pool/test_dhcp.py --image /path/to/unikernel.hvt
The image must log `Lease obtained! IP: ADDRESS` and need no boot arguments.
No image build or application dependency is part of this launcher test.
"""
import argparse
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]


def normalize(mac):
    return ':'.join(f'{int(part, 16):02x}' for part in mac.split(':'))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, type=Path)
    parser.add_argument('--tender', type=Path, default=ROOT / 'tenders/hvt/solo5-hvt')
    parser.add_argument('--boots', type=int, default=12)
    args = parser.parse_args()
    if args.boots < 2:
        parser.error('--boots must be at least 2')
    addresses = set()
    with tempfile.TemporaryDirectory(prefix='solo5-dhcp-reuse-') as directory:
        for boot in range(args.boots):
            command = [str(ROOT / 'tenders/vmnet/solo5-vmnet'),
                       '--pool-dir=' + directory, '--pool-size=1', '--',
                       str(args.tender.resolve()), '--mem=256', '--',
                       str(args.image.resolve())]
            guest = subprocess.Popen(command, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, start_new_session=True)
            started = time.monotonic()
            output = b''
            try:
                deadline = started + 60
                while time.monotonic() < deadline:
                    if not select.select([guest.stdout], [], [], 0.2)[0]:
                        continue
                    chunk = os.read(guest.stdout.fileno(), 65536)
                    if not chunk:
                        raise AssertionError('guest exited before DHCP: ' + output.decode(errors='replace'))
                    output += chunk
                    lease = re.search(rb'Lease obtained! IP: ([0-9.]+)', output)
                    if lease:
                        addresses.add(lease[1].decode())
                        print(f'boot {boot + 1}: DHCP ready in {time.monotonic() - started:.3f}s', flush=True)
                        break
                else:
                    raise AssertionError('DHCP timeout: ' + output.decode(errors='replace'))
            finally:
                if guest.poll() is None:
                    os.killpg(guest.pid, signal.SIGTERM)
                try:
                    guest.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(guest.pid, signal.SIGKILL)
                    guest.wait(timeout=5)
                guest.stdout.close()
        identities = list(Path(directory).glob('*.identity'))
        assert len(identities) == 1, 'repeated boots allocated more than one identity'
        _, mac = identities[0].read_text().split()
        leases = []
        for block in re.findall(r'\{(.*?)\}', Path('/var/db/dhcpd_leases').read_text(), re.S):
            hardware = re.search(r'hw_address=1,(\S+)', block)
            if hardware and normalize(hardware[1]) == normalize(mac):
                leases.append(block)
        assert len(leases) == 1, f'expected one host lease for pooled MAC, found {len(leases)}'
        print(f'PASS: {args.boots} real boots, one persistent identity, one DHCP lease; IPs: {sorted(addresses)}')


if __name__ == '__main__':
    main()
