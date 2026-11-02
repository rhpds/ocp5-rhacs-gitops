"""Exercise recovery logic with a fake oc; never connects to a cluster."""
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

from test_convergence import render

FAKE_OC = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
p = pathlib.Path(os.environ['FAKE_STATE'])
s = json.loads(p.read_text())
a = sys.argv[1:]
def save(): p.write_text(json.dumps(s))
if a[:2] == ['get', 'buildconfig']:
    print('config-uid:' + str(s.get('generation', 1)))
elif a[:2] == ['get', 'builds']:
    print(s.get('latest', ''))
elif a[:2] == ['get', 'build']:
    print(s.get('signature', '') if 'annotations' in a[-1] else s.get('phase', 'Complete'))
elif a[:1] == ['start-build']:
    s['starts'] = s.get('starts', 0) + 1
    s['latest'] = 'test-' + str(s['starts'])
    s['phase'] = 'Complete'
    save()
    print('build.build.openshift.io/' + s['latest'])
elif a[:2] == ['annotate', 'build']:
    s['signature'] = next(v.split('=', 1)[1] for v in a if v.startswith('roadshow.rhpds.com/build-inputs='))
    save()
elif a[:2] == ['get', 'deployment']:
    s['checks'] = s.get('checks', 0) + 1
    save()
    sys.exit(0 if s['checks'] > s.get('missing_checks', 0) else 1)
elif a[:1] == ['extract']:
    if not s.get('ca_ready'):
        sys.exit(1)
    directory = next(v.split('=', 1)[1] for v in a if v.startswith('--to='))
    pathlib.Path(directory, 'ca.pem').write_text('test-certificate')
elif a[:3] == ['create', 'secret', 'generic']:
    print('fake-secret-manifest')
elif a[:1] == ['apply']:
    sys.stdin.read()
    if s.get('apply_fails'):
        sys.exit(1)
    s['applied'] = True
    save()
else:
    raise RuntimeError('Unexpected fake oc invocation: ' + repr(a))
'''


class RecoveryScriptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name)
        self.state = self.directory / 'state.json'
        self.state.write_text('{}')
        oc = self.directory / 'oc'
        oc.write_text(FAKE_OC)
        oc.chmod(0o755)
        sleep = self.directory / 'sleep'
        sleep.write_text('#!/bin/sh\nexit 0\n')
        sleep.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.directory) + os.pathsep + os.environ['PATH'],
                        FAKE_STATE=str(self.state))
        job = next(d for d in render('agentic-updates-builds') if d['kind'] == 'Job')
        script = job['spec']['template']['spec']['containers'][0]['args'][0]
        self.functions = script.split('# ── Step 1:')[0]

    def run_script(self, script):
        return subprocess.run(['bash', '-c', script], env=self.env, text=True,
                              capture_output=True, timeout=10)

    def test_retry_reuses_build_until_inputs_or_config_change(self):
        for inputs, generation, starts in [('images-a', 1, 1), ('images-a', 1, 1),
                                           ('images-b', 1, 2), ('images-b', 2, 3)]:
            state = json.loads(self.state.read_text())
            state['generation'] = generation
            self.state.write_text(json.dumps(state))
            result = self.run_script(self.functions + '\nensure_build test 10 ' + inputs)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(self.state.read_text())['starts'], starts)

    def test_target_can_appear_after_initial_checks(self):
        self.state.write_text(json.dumps({'missing_checks': 2}))
        result = self.run_script(self.functions + '\nwait_for_deployment test target 30')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.state.read_text())['checks'], 3)

    def test_missing_target_times_out(self):
        self.state.write_text(json.dumps({'missing_checks': 100}))
        result = self.run_script(self.functions + '\nwait_for_deployment test target 0')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Timed out', result.stdout)

    def ca_script(self):
        cron = next(d for d in render('rhacs-mcp-server-prereqs') if d['kind'] == 'CronJob')
        return cron['spec']['jobTemplate']['spec']['template']['spec']['containers'][0]['args'][0]

    def test_ca_recovers_on_later_scheduled_run(self):
        result = self.run_script(self.ca_script())
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(json.loads(self.state.read_text()).get('applied'))
        self.state.write_text(json.dumps({'ca_ready': True}))
        result = self.run_script(self.ca_script())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(self.state.read_text())['applied'])

    def test_ca_apply_failure_is_not_reported_as_success(self):
        self.state.write_text(json.dumps({'ca_ready': True, 'apply_fails': True}))
        result = self.run_script(self.ca_script())
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('reconciled successfully', result.stdout)
