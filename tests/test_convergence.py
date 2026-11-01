"""Run with: python -m unittest discover -s tests (requires PyYAML and Helm)."""
import pathlib
import subprocess
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]


def render(chart, release="test"):
    return [doc for doc in yaml.safe_load_all(subprocess.check_output(
        ["helm", "template", release, str(ROOT / chart)], text=True
    )) if doc]


class ConvergenceTests(unittest.TestCase):
    def test_policy_fields_survive_installed_schema(self):
        names = {"eap-init-test-fixable-important-cve", "eap-init-test-privileged-container"}
        policies = [d for d in render("rhacs-operator/instance")
                    if d["kind"] == "SecurityPolicy" and d["metadata"]["name"] in names]
        self.assertEqual(len(policies), 2)
        for doc in policies:
            self.assertNotIn("policyVersion", doc["spec"])
            self.assertTrue(doc["spec"]["policySections"])

    def test_alert_filter_is_preserved(self):
        doc = next(d for d in render("openshift-lightspeed-troubleshooting")
                   if d["kind"] == "AlertmanagerConfig")
        self.assertEqual(doc["spec"]["route"]["matchers"], [{
            "name": "alertname", "matchType": "=", "value": "WorkshopBlackholeNeverFires"
        }])
        self.assertNotIn("match", doc["spec"]["route"])

    def test_ctf_is_owned_by_one_source(self):
        app = next(d for d in render("app-of-apps")
                   if d["metadata"]["name"] == "roadshow-demo-apps")
        self.assertNotIn("source", app["spec"])
        sources = app["spec"]["sources"]
        self.assertIn("ctf-web-to-system/**", sources[0]["directory"]["exclude"])
        self.assertEqual(sources[1]["path"], "roadshow-ctf")
        docs = list(yaml.safe_load_all((ROOT / "roadshow-ctf/resources.yaml").read_text()))
        svc = next(d for d in docs if d["kind"] == "Service")
        deployment = next(d for d in docs if d["kind"] == "Deployment")
        self.assertEqual(svc["spec"]["type"], "ClusterIP")
        self.assertEqual(svc["spec"]["selector"], deployment["spec"]["template"]["metadata"]["labels"])
        self.assertNotIn("annotation", deployment["metadata"])

    def test_tekton_namespace_markers_are_ignored_narrowly(self):
        app = next(d for d in render("app-of-apps")
                   if d["metadata"]["name"] == "roadshow-demo-apps")
        rule = next(r for r in app["spec"]["ignoreDifferences"] if r["kind"] == "Namespace")
        markers = [p for p in rule["jqPathExpressions"] if "openshift-pipelines.tekton.dev/" in p]
        self.assertEqual(set(markers), {
            '.metadata.labels["openshift-pipelines.tekton.dev/namespace-reconcile-version"]',
            '.metadata.labels["openshift-pipelines.tekton.dev/namespace-trusted-configmaps-version"]',
        })

    def test_core_group_omission_does_not_drift(self):
        app = next(d for d in render("lightwell-tssc")
                   if d["metadata"]["name"] == "test-admission")
        for rule in app["spec"]["ignoreDifferences"]:
            self.assertNotEqual(rule.get("group"), "")

    def test_ca_copy_is_bounded_and_fail_fast(self):
        job = next(d for d in render("rhacs-mcp-server-prereqs") if d["kind"] == "Job")
        self.assertEqual(job["spec"]["activeDeadlineSeconds"], 1020)
        script = job["spec"]["template"]["spec"]["containers"][0]["args"][0]
        self.assertIn("set -euo pipefail", script)
        self.assertIn("SECONDS + 900", script)
        self.assertIn("SECONDS >= deadline", script)
        self.assertIn('--request-timeout=10s', script)
        subprocess.run(["bash", "-n"], input=script, text=True, check=True)


if __name__ == "__main__":
    unittest.main()
