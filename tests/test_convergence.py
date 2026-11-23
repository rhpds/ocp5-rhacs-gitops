"""Run with: python -m unittest discover -s tests (requires PyYAML and Helm)."""
import pathlib
import subprocess
import unittest

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]


def render(chart, release="test", sets=None):
    command = ["helm", "template", release, str(ROOT / chart)]
    for item in sets or []:
        command.extend(["--set", item])
    return [doc for doc in yaml.safe_load_all(subprocess.check_output(
        command, text=True
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
        for app in render("lightwell-tssc"):
            if app["kind"] != "Application":
                continue
            for rule in app["spec"].get("ignoreDifferences", []):
                self.assertNotEqual(rule.get("group"), "", app["metadata"]["name"])

    def test_platform_sso_uses_bounded_internal_admin_requests(self):
        job = next(d for d in render("platform-sso") if d["kind"] == "Job")
        script = job["spec"]["template"]["spec"]["containers"][0]["args"][0]
        self.assertIn('ADMIN_URL="https://keycloak.keycloak.svc:8443"', script)
        self.assertIn('SSO_URL="https://sso.', script)
        self.assertNotIn("${SSO_URL}/", script)
        self.assertIn('--data-urlencode "password=${ADMIN_PASS}"', script)
        self.assertEqual(job["spec"]["activeDeadlineSeconds"], 600)
        for line in script.splitlines():
            if "curl " in line:
                self.assertIn("--connect-timeout 5 --max-time 30", line)
                self.assertIn("-fsSk", line)
        subprocess.run(["bash", "-n"], input=script, text=True, check=True)
        rendered = render("lightwell-tssc", sets=["deployer.domain=apps.example.com"])
        rhtpa = next(doc for doc in rendered if doc["metadata"]["name"].endswith("-rhtpa"))
        issuer = rhtpa["spec"]["source"]["helm"]["valuesObject"]["oidc"]["issuerURL"]
        self.assertEqual(issuer, "https://sso.apps.example.com/realms/keycloak")
        for doc in rendered:
            if doc["kind"] != "Application":
                continue
            for rule in doc["spec"].get("ignoreDifferences", []):
                self.assertNotEqual(rule.get("group"), "", doc["metadata"]["name"])
        quay = next(doc for doc in render(
            "quay", sets=["clusterSubdomain=apps.example.com", "adminPassword=workshop"]
        ) if doc["kind"] == "Secret" and doc["metadata"]["name"] == "quay-config-bundle-v3")
        config = quay["stringData"]["config.yaml"]
        self.assertIn("AUTHENTICATION_TYPE: OIDC", config)
        self.assertIn("FEATURE_DIRECT_LOGIN: true", config)
        self.assertIn("https://sso.apps.example.com/realms/keycloak", config)

    def test_keycloak_bootstrap_uses_bounded_internal_admin_requests(self):
        job = next(d for d in render("openshift-mcp-server") if d["kind"] == "Job")
        script = job["spec"]["template"]["spec"]["containers"][0]["args"][0]
        self.assertIn('ADMIN_URL="https://keycloak.keycloak.svc:8443"', script)
        self.assertIn('SSO_URL="https://sso.', script)
        self.assertNotIn('${SSO_URL}/', script)
        self.assertIn('--data-urlencode "password=${ADMIN_PASS}"', script)
        self.assertEqual(job["spec"]["activeDeadlineSeconds"], 600)
        for line in script.splitlines():
            if 'curl ' in line:
                self.assertIn('--connect-timeout 5 --max-time 30', line)
                self.assertIn('-fsSk', line)
        subprocess.run(["bash", "-n"], input=script, text=True, check=True)

    def test_vsock_waits_for_real_admission(self):
        docs = render("rhacs-virt")
        job = next(d for d in docs if d["kind"] == "Job")
        script = job["spec"]["template"]["spec"]["containers"][0]["args"][0]
        self.assertIn('set -euo pipefail', script)
        self.assertIn('until gate_enabled && oc create --dry-run=server', script)
        self.assertIn('SECONDS + 600', script)
        role = next(d for d in docs if d["kind"] == "Role")
        self.assertEqual(role["rules"][0]["resources"], ["virtualmachines"])
        self.assertEqual(role["rules"][0]["verbs"], ["create"])
        reader = next(d for d in docs if d["kind"] == "ClusterRole")
        self.assertTrue(any(r["resources"] == ["kubevirts"] and r["verbs"] == ["get"]
                            for r in reader["rules"]))
        subprocess.run(["bash", "-n"], input=script, text=True, check=True)

    def test_ca_copy_reconciles_after_failed_runs(self):
        cron = next(d for d in render("rhacs-mcp-server-prereqs") if d["kind"] == "CronJob")
        self.assertEqual(cron["spec"]["schedule"], "* * * * *")
        self.assertEqual(cron["spec"]["concurrencyPolicy"], "Forbid")
        self.assertNotIn("argocd.argoproj.io/hook", cron["metadata"].get("annotations", {}))
        job = cron["spec"]["jobTemplate"]["spec"]
        self.assertEqual(job["activeDeadlineSeconds"], 90)
        script = job["template"]["spec"]["containers"][0]["args"][0]
        self.assertIn("set -euo pipefail", script)
        self.assertIn('--request-timeout=15s', script)
        subprocess.run(["bash", "-n"], input=script, text=True, check=True)

    def test_quay_declares_operator_defaults(self):
        registry = next(d for d in render("quay") if d["kind"] == "QuayRegistry")
        components = registry["spec"]["components"]
        self.assertEqual(len(components), 11)
        self.assertEqual(len({c["kind"] for c in components}), len(components))
        for kind in ("quay", "clairpostgres"):
            self.assertEqual(next(c for c in components if c["kind"] == kind),
                             {"kind": kind, "managed": True})

    def test_acm_uses_live_catalog_and_enables_console(self):
        app = next(d for d in render("app-of-apps") if d["metadata"]["name"] == "acm")
        self.assertEqual(app["spec"]["source"]["path"], "acm")
        values = app["spec"]["source"]["helm"]["valuesObject"]["subscription"]
        self.assertEqual(values["source"], "redhat-operators")
        self.assertEqual(values["channel"], "release-5.0")
        ignored = next(r for r in app["spec"]["ignoreDifferences"]
                       if r["kind"] == "MultiClusterHub")
        self.assertEqual(set(ignored["jqPathExpressions"]), {
            ".spec.overrides",
            ".spec.localClusterName",
            ".spec.networkPolicies",
        })
        docs = [doc for doc in yaml.safe_load_all(subprocess.check_output(
            ["helm", "template", "acm", str(ROOT / "acm"),
             "--namespace", "open-cluster-management"],
            text=True,
        )) if doc]
        sub = next(d for d in docs if d["kind"] == "Subscription")
        self.assertEqual(sub["spec"]["name"], "advanced-cluster-management")
        self.assertEqual(sub["spec"]["source"], "redhat-operators")
        self.assertEqual(sub["spec"]["channel"], "release-5.0")
        self.assertEqual(sub["metadata"]["namespace"], "open-cluster-management")
        hub = next(d for d in docs if d["kind"] == "MultiClusterHub")
        self.assertEqual(hub["metadata"]["name"], "multiclusterhub")
        self.assertEqual(hub["spec"]["availabilityConfig"], "Basic")
        job = next(d for d in docs if d["kind"] == "Job")
        script = job["spec"]["template"]["spec"]["containers"][0]["args"][0]
        self.assertIn('PLUGIN="acm"', script)
        self.assertIn("console.operator.openshift.io cluster", script)
        subprocess.run(["bash", "-n"], input=script, text=True, check=True)

    def test_build_job_can_be_retried_and_waits_for_target(self):
        job = next(d for d in render("agentic-updates-builds") if d["kind"] == "Job")
        self.assertNotIn("argocd.argoproj.io/hook", job["metadata"]["annotations"])
        self.assertEqual(job["metadata"]["annotations"]["argocd.argoproj.io/sync-options"],
                         "Force=true,Replace=true")
        self.assertGreaterEqual(job["spec"]["activeDeadlineSeconds"], 3600)
        script = job["spec"]["template"]["spec"]["containers"][0]["args"][0]
        self.assertLess(script.index("wait_for_deployment openshift-cluster-update-console-plugin"),
                        script.index("oc set image deployment/cluster-update-console-plugin"))
        self.assertIn('wait "$PID1" || build_failed=1', script)
        self.assertIn('wait "$PID2" || build_failed=1', script)
        subprocess.run(["bash", "-n"], input=script, text=True, check=True)

    def test_failed_bootstrap_apps_can_finish_one_sync(self):
        policies = [d for d in render("cluster-update") if d["kind"] == "NetworkPolicy"]
        self.assertEqual(len(policies), 2)
        for policy in policies:
            allowed = {(port["port"], port["protocol"]) for port in policy["spec"]["egress"][0]["ports"]}
            self.assertIn((443, "TCP"), allowed)
            self.assertIn((6443, "TCP"), allowed)
            self.assertIn((53, "UDP"), allowed)
            self.assertIn((53, "TCP"), allowed)
        jobs = [d for d in render("cluster-update") if d["kind"] == "Job"]
        self.assertEqual({job["metadata"]["name"] for job in jobs},
                         {"fauxinnati", "cloud-credential-manual"})
        for job in jobs:
            self.assertEqual(job["metadata"]["annotations"]["argocd.argoproj.io/sync-options"],
                             "Force=true,Replace=true")
            script = job["spec"]["template"]["spec"]["containers"][0]["args"][0]
            self.assertIn("--request-timeout=15s", script)
            subprocess.run(["bash", "-n"], input=script, text=True, check=True)
        credential = next(job for job in jobs if job["metadata"]["name"] == "cloud-credential-manual")
        credential_script = credential["spec"]["template"]["spec"]["containers"][0]["args"][0]
        patch_at = credential_script.index("if ! oc --request-timeout=15s patch cloudcredential cluster")
        annotate_at = credential_script.index('cloudcredential.openshift.io/upgradeable-to="5.1.0"')
        self.assertLess(patch_at, annotate_at)
        self.assertNotIn("exit", credential_script[patch_at:annotate_at])

        java = []
        for path in sorted((ROOT / "lightwell-java").glob("*.yaml")):
            java.extend(doc for doc in yaml.safe_load_all(path.read_text()) if doc)
        build = next(d for d in java if d["kind"] == "BuildConfig")
        self.assertFalse(build["spec"].get("triggers"))
        deployment = next(d for d in java if d["kind"] == "Deployment")
        build_job = next(d for d in java if d["kind"] == "Job"
                          and d["metadata"]["name"] == "help-im-vulnerable-build")
        digest = next(d for d in java if d["metadata"]["name"] == "help-im-vulnerable-record-digest")

        def wave(doc):
            return int(doc["metadata"]["annotations"]["argocd.argoproj.io/sync-wave"])

        self.assertLess(wave(build_job), wave(deployment))
        self.assertLess(wave(deployment), wave(digest))
        self.assertEqual(wave(build_job), 4)
        self.assertGreaterEqual(deployment["spec"]["progressDeadlineSeconds"], 3600)
        self.assertEqual(build_job["metadata"]["annotations"]["argocd.argoproj.io/sync-options"],
                         "Force=true,Replace=true")
        self.assertGreaterEqual(build_job["spec"]["activeDeadlineSeconds"], 3000)
        self.assertEqual(digest["metadata"]["annotations"]["argocd.argoproj.io/sync-options"],
                         "Force=true,Replace=true")
        self.assertGreaterEqual(digest["spec"]["backoffLimit"], 5)
        role = next(d for d in java if d["kind"] == "Role")
        instantiate = next(rule for rule in role["rules"]
                           if rule["resources"] == ["buildconfigs/instantiate"])
        self.assertEqual(instantiate["verbs"], ["create"])
        builds = next(rule for rule in role["rules"] if rule["resources"] == ["builds"])
        self.assertEqual(set(builds["verbs"]), {"get", "list"})
        build_script = build_job["spec"]["template"]["spec"]["containers"][0]["args"][0]
        self.assertLess(build_script.index("get serviceaccount builder"),
                        build_script.index("start-build"))
        self.assertIn("Failed|Error)", build_script)
        subprocess.run(["bash", "-n"], input=build_script, text=True, check=True)

        quay = render("quay", sets=["adminPassword=workshop", "clusterSubdomain=apps.example.com"])
        init = next(d for d in quay if d["kind"] == "Job" and d["metadata"]["name"] == "quay-init-user")
        self.assertNotIn("argocd.argoproj.io/hook", init["metadata"]["annotations"])
        self.assertNotIn("argocd.argoproj.io/hook-delete-policy", init["metadata"]["annotations"])
        self.assertEqual(init["metadata"]["annotations"]["argocd.argoproj.io/sync-options"],
                         "Force=true,Replace=true")
        self.assertGreaterEqual(init["spec"]["activeDeadlineSeconds"], 2400)
        init_container = init["spec"]["template"]["spec"]["containers"][0]
        init_script = (init_container.get("args") or init_container["command"])[-1]
        curl_lines = [line for line in init_script.splitlines() if "curl " in line]
        self.assertGreaterEqual(len(curl_lines), 2)
        for line in curl_lines:
            self.assertIn("--connect-timeout 5 --max-time 30", line)
        subprocess.run(["bash", "-n"], input=init_script, text=True, check=True)
        images = next(d for d in quay if d["kind"] == "Job" and d["metadata"]["name"] == "workshop-images")
        self.assertEqual(images["metadata"]["annotations"]["argocd.argoproj.io/sync-options"],
                         "Force=true,Replace=true")
        self.assertGreaterEqual(images["spec"]["activeDeadlineSeconds"], 2400)


if __name__ == "__main__":
    unittest.main()
