#!/usr/bin/env python3
"""macOS integration tests: real vmnet interfaces, disposable stand-in tenders.

Run after make: python3 tests/vmnet_pool/test_pool.py
The launcher must have its virtualization entitlement. No root is needed.
"""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / 'tenders/vmnet/solo5-vmnet'


class PoolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='solo5-vmnet-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pool = self.root / 'pool'
        self.tender = self.root / 'tender'
        self.tender.write_text('''#!/usr/bin/env python3
import json, os, sys, time
print(json.dumps({'pid': os.getpid(), 'args': sys.argv[1:]}), flush=True)
if os.environ.get('POOL_TEST_HOLD') == '1':
    time.sleep(120)
''')
        self.tender.chmod(0o700)

    def command(self, *options):
        return [str(LAUNCHER), '--pool-dir=' + str(self.pool),
                '--pool-size=2', *options, '--', str(self.tender)]

    def run_guest(self, *options):
        result = subprocess.run(self.command(*options), capture_output=True,
                                text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.mac(json.loads(result.stdout))

    @staticmethod
    def mac(info):
        return next(arg.split('=', 1)[1] for arg in info['args']
                    if arg.startswith('--net-mac:'))

    def hold_guest(self, *options):
        process = subprocess.Popen(self.command(*options), stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True,
                                   env={**os.environ, 'POOL_TEST_HOLD': '1'},
                                   start_new_session=True)
        self.addCleanup(self.stop, process)
        return process

    @staticmethod
    def stop(process):
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()

    def ready(self, process):
        self.assertTrue(select.select([process.stdout], [], [], 15)[0],
                        'guest did not start')
        line = process.stdout.readline()
        self.assertTrue(line, 'launcher exited before guest readiness')
        return json.loads(line)

    def test_repeated_launches_reuse_one_identity(self):
        addresses = {self.run_guest() for _ in range(20)}
        self.assertEqual(len(addresses), 1)
        self.assertEqual(len(list(self.pool.glob('*.identity'))), 1)

    def test_concurrent_guests_and_backpressure(self):
        first = self.hold_guest()
        a = self.ready(first)
        second = self.hold_guest()
        b = self.ready(second)
        self.assertNotEqual(self.mac(a), self.mac(b))
        third = self.hold_guest()
        self.assertFalse(select.select([third.stdout], [], [], 0.4)[0],
                         'third guest bypassed the full pool')
        first.terminate()
        self.assertEqual(first.wait(timeout=10), 128 + signal.SIGTERM)
        c = self.ready(third)
        self.assertEqual(self.mac(a), self.mac(c))
        self.assertEqual(len(list(self.pool.glob('*.identity'))), 2)

    def test_killed_launcher_releases_lock(self):
        first = self.hold_guest('--pool-size=1')
        a = self.ready(first)
        first.kill()
        first.wait(timeout=5)
        # The stand-in tender has no parent-death handling. Clean up that
        # test-owned process explicitly, as real process-group cleanup does.
        os.kill(a['pid'], signal.SIGTERM)
        time.sleep(0.3)
        self.assertEqual(self.run_guest('--pool-size=1'), self.mac(a))

    def test_corruption_does_not_allocate_a_new_identity(self):
        self.run_guest()
        record = next(self.pool.glob('*.identity'))
        record.write_text('corrupt\n')
        result = subprocess.run(self.command(), capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('refusing to allocate a replacement', result.stderr)
        self.assertEqual(record.read_text(), 'corrupt\n')

    def test_saved_mac_mismatch_fails_closed(self):
        self.run_guest()
        record = next(self.pool.glob('*.identity'))
        identity, _ = record.read_text().split()
        record.write_text(identity + ' 02:00:00:00:00:01\n')
        result = subprocess.run(self.command(), capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('refusing replacement', result.stderr)

    def test_private_pool_and_option_validation(self):
        result = subprocess.run(self.command('--pool-size=0'), capture_output=True,
                                text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.pool.mkdir(mode=0o755)
        self.pool.chmod(0o755)
        result = subprocess.run(self.command(), capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('must be private', result.stderr)

    def test_environment_defaults(self):
        env = {**os.environ, 'SOLO5_VMNET_POOL_DIR': str(self.pool),
               'SOLO5_VMNET_POOL_SIZE': '1'}
        addresses = set()
        for _ in range(2):
            result = subprocess.run([str(LAUNCHER), '--', str(self.tender)],
                                    capture_output=True, text=True, timeout=15, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            addresses.add(self.mac(json.loads(result.stdout)))
        self.assertEqual(len(addresses), 1)
        self.assertEqual(len(list(self.pool.glob('*.identity'))), 1)

    def test_symlink_lock_is_refused(self):
        self.pool.mkdir(mode=0o700)
        target = self.root / 'unrelated'
        target.write_text('keep this content')
        (self.pool / 'shared-0.lock').symlink_to(target)
        result = subprocess.run(self.command(), capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_text(), 'keep this content')
        self.assertEqual(len(list(self.pool.glob('*.identity'))), 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
