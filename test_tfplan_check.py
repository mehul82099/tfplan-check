import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tfplan_check as tc


def rc(address, rtype, actions, mode="managed", extra_change=None):
    change = {"actions": list(actions)}
    if extra_change:
        change.update(extra_change)
    return {
        "address": address,
        "mode": mode,
        "type": rtype,
        "name": address.split(".")[-1],
        "change": change,
    }


def plan(*changes):
    return {"format_version": "1.2", "resource_changes": list(changes)}


class LoadPlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_loads_valid_plan(self):
        path = self.write("p.json", json.dumps(plan()))
        self.assertEqual(tc.load_plan(path)["resource_changes"], [])

    def test_missing_file(self):
        with self.assertRaises(tc.PlanError) as ctx:
            tc.load_plan(os.path.join(self.dir, "nope.json"))
        self.assertIn("cannot read", str(ctx.exception))

    def test_invalid_json_mentions_terraform_show(self):
        path = self.write("p.json", "not json {")
        with self.assertRaises(tc.PlanError) as ctx:
            tc.load_plan(path)
        self.assertIn("terraform show -json", str(ctx.exception))

    def test_top_level_array_rejected(self):
        path = self.write("p.json", "[]")
        with self.assertRaises(tc.PlanError) as ctx:
            tc.load_plan(path)
        self.assertIn("top level", str(ctx.exception))

    def test_missing_resource_changes(self):
        path = self.write("p.json", json.dumps({"format_version": "1.2"}))
        with self.assertRaises(tc.PlanError) as ctx:
            tc.load_plan(path)
        self.assertIn("resource_changes", str(ctx.exception))

    def test_resource_changes_not_a_list(self):
        path = self.write("p.json", json.dumps({"resource_changes": {}}))
        with self.assertRaises(tc.PlanError):
            tc.load_plan(path)

    def test_utf8_plan_loads(self):
        p = plan(rc("aws_instance.web", "aws_instance", ["create"],
                    extra_change={"after": {"tag": "héllo"}}))
        path = self.write("p.json", json.dumps(p))
        self.assertEqual(len(tc.load_plan(path)["resource_changes"]), 1)


class AllowFileTests(unittest.TestCase):
    def test_parses_lines_and_comments(self):
        with tempfile.NamedTemporaryFile(
                "w", suffix=".txt", delete=False) as fh:
            fh.write("# comment\naws_s3_bucket.logs\n\n"
                     "aws_db_instance.main  # trailing comment\n")
            path = fh.name
        try:
            self.assertEqual(tc.load_allow_file(path),
                             ["aws_s3_bucket.logs", "aws_db_instance.main"])
        finally:
            os.unlink(path)

    def test_missing_allow_file(self):
        with self.assertRaises(tc.PlanError) as ctx:
            tc.load_allow_file("/nonexistent/allow.txt")
        self.assertIn("cannot read allow file", str(ctx.exception))


class CheckPlanTests(unittest.TestCase):
    def check(self, p, protected=None, allowed=()):
        if protected is None:
            protected = set(tc.DEFAULT_PROTECTED_TYPES)
        return tc.check_plan(p, protected, list(allowed))

    def test_empty_plan_is_clean(self):
        findings, summary, suppressed = self.check(plan())
        self.assertEqual(findings, [])
        self.assertEqual(suppressed, [])

    def test_noop_is_clean(self):
        f, s, _ = self.check(plan(rc("aws_instance.a", "aws_instance",
                                     ["no-op"])))
        self.assertEqual(f, [])
        self.assertEqual(s["no-op"], 1)

    def test_read_is_clean(self):
        f, s, _ = self.check(plan(rc("aws_instance.a", "aws_instance",
                                     ["read"])))
        self.assertEqual(f, [])
        self.assertEqual(s["read"], 1)

    def test_create_is_clean(self):
        f, s, _ = self.check(plan(rc("aws_s3_bucket.b", "aws_s3_bucket",
                                     ["create"])))
        self.assertEqual(f, [])
        self.assertEqual(s["create"], 1)

    def test_update_unprotected_is_clean(self):
        f, s, _ = self.check(plan(rc("aws_instance.a", "aws_instance",
                                     ["update"])))
        self.assertEqual(f, [])
        self.assertEqual(s["update"], 1)

    def test_destroy_is_error(self):
        f, s, _ = self.check(plan(rc("aws_instance.a", "aws_instance",
                                     ["delete"])))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].rule, "resource-destroy")
        self.assertEqual(f[0].severity, "error")
        self.assertEqual(f[0].address, "aws_instance.a")
        self.assertEqual(s["delete"], 1)

    def test_replace_delete_create_is_error(self):
        f, s, _ = self.check(plan(rc("aws_instance.a", "aws_instance",
                                     ["delete", "create"])))
        self.assertEqual(f[0].rule, "resource-replace")
        self.assertEqual(f[0].severity, "error")
        self.assertEqual(s["replace"], 1)

    def test_replace_create_delete_is_error(self):
        f, _, _ = self.check(plan(rc("aws_instance.a", "aws_instance",
                                     ["create", "delete"])))
        self.assertEqual(f[0].rule, "resource-replace")

    def test_protected_type_update_is_warning(self):
        f, _, _ = self.check(plan(rc("aws_db_instance.main",
                                     "aws_db_instance", ["update"])))
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].rule, "protected-update")
        self.assertEqual(f[0].severity, "warning")
        self.assertIn("aws_db_instance", f[0].message)

    def test_protected_type_destroy_names_type(self):
        f, _, _ = self.check(plan(rc("aws_db_instance.main",
                                     "aws_db_instance", ["delete"])))
        self.assertEqual(f[0].rule, "resource-destroy")
        self.assertIn("protected resource type", f[0].message)

    def test_protected_type_replace_names_type(self):
        f, _, _ = self.check(plan(rc("google_storage_bucket.b",
                                     "google_storage_bucket",
                                     ["delete", "create"])))
        self.assertEqual(f[0].rule, "resource-replace")
        self.assertIn("protected resource type", f[0].message)

    def test_data_mode_entries_are_skipped(self):
        f, s, _ = self.check(plan(rc("data.aws_ami.ubuntu", "aws_ami",
                                     ["read"], mode="data")))
        self.assertEqual(f, [])
        self.assertEqual(s["data-skipped"], 1)

    def test_allow_suppresses_destroy(self):
        f, _, sup = self.check(
            plan(rc("aws_s3_bucket.old", "aws_s3_bucket", ["delete"])),
            allowed=["aws_s3_bucket.old"])
        self.assertEqual(f, [])
        self.assertEqual(len(sup), 1)
        self.assertEqual(sup[0].address, "aws_s3_bucket.old")

    def test_allow_does_not_suppress_other_addresses(self):
        f, _, _ = self.check(
            plan(rc("aws_s3_bucket.old", "aws_s3_bucket", ["delete"]),
                 rc("aws_s3_bucket.other", "aws_s3_bucket", ["delete"])),
            allowed=["aws_s3_bucket.old"])
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].address, "aws_s3_bucket.other")

    def test_allow_suppresses_protected_update(self):
        f, _, sup = self.check(
            plan(rc("aws_db_instance.main", "aws_db_instance", ["update"])),
            allowed=["aws_db_instance.main"])
        self.assertEqual(f, [])
        self.assertEqual(len(sup), 1)

    def test_custom_protect_type(self):
        f, _, _ = self.check(
            plan(rc("aws_instance.a", "aws_instance", ["update"])),
            protected={"aws_instance"})
        self.assertEqual(f[0].rule, "protected-update")

    def test_empty_protect_set_disables_defaults(self):
        f, _, _ = self.check(
            plan(rc("aws_db_instance.main", "aws_db_instance", ["update"])),
            protected=set())
        self.assertEqual(f, [])

    def test_module_address_matches_exactly(self):
        f, _, _ = self.check(
            plan(rc("module.vpc.aws_s3_bucket.logs", "aws_s3_bucket",
                    ["delete"])),
            allowed=["module.vpc.aws_s3_bucket.logs"])
        self.assertEqual(f, [])

    def test_unknown_actions_rejected(self):
        with self.assertRaises(tc.PlanError) as ctx:
            self.check(plan(rc("aws_instance.a", "aws_instance",
                               ["explode"])))
        self.assertIn("unknown change.actions", str(ctx.exception))

    def test_missing_change_rejected(self):
        with self.assertRaises(tc.PlanError):
            self.check({"resource_changes": [
                {"address": "aws_instance.a", "type": "aws_instance"}]})

    def test_missing_address_rejected(self):
        with self.assertRaises(tc.PlanError) as ctx:
            self.check({"resource_changes": [
                {"type": "aws_instance", "change": {"actions": ["update"]}}]})
        self.assertIn("address", str(ctx.exception))

    def test_non_object_entry_rejected(self):
        with self.assertRaises(tc.PlanError):
            self.check({"resource_changes": ["nope"]})

    def test_non_string_actions_rejected(self):
        with self.assertRaises(tc.PlanError):
            self.check({"resource_changes": [
                {"address": "a.b", "type": "b",
                 "change": {"actions": [1]}}]})

    def test_summary_counts_all_categories(self):
        p = plan(
            rc("aws_instance.a", "aws_instance", ["create"]),
            rc("aws_instance.b", "aws_instance", ["update"]),
            rc("aws_instance.c", "aws_instance", ["delete"]),
            rc("aws_instance.d", "aws_instance", ["delete", "create"]),
            rc("aws_instance.e", "aws_instance", ["no-op"]),
            rc("aws_instance.f", "aws_instance", ["read"]),
        )
        _, s, _ = self.check(p)
        self.assertEqual((s["create"], s["update"], s["delete"],
                          s["replace"], s["no-op"], s["read"]),
                         (1, 1, 1, 1, 1, 1))

    def test_default_protected_list_is_nonempty(self):
        self.assertGreater(len(tc.DEFAULT_PROTECTED_TYPES), 10)
        self.assertIn("aws_db_instance", tc.DEFAULT_PROTECTED_TYPES)
        self.assertIn("google_storage_bucket", tc.DEFAULT_PROTECTED_TYPES)
        self.assertIn("azurerm_storage_account", tc.DEFAULT_PROTECTED_TYPES)


class FormatTests(unittest.TestCase):
    def test_text_clean(self):
        out = tc.format_text([], {"create": 1, "update": 0, "delete": 0,
                                  "replace": 0, "no-op": 2, "read": 0,
                                  "data-skipped": 0}, [])
        self.assertIn("plan is clean", out)
        self.assertIn("1 to create", out)

    def test_text_counts_errors_and_warnings(self):
        findings = [
            tc.Finding("resource-destroy", "error", "a.b", "a.b will be destroyed."),
            tc.Finding("protected-update", "warning", "c.d", "c.d will be updated."),
        ]
        out = tc.format_text(findings, {"create": 0, "update": 1, "delete": 1,
                                        "replace": 0, "no-op": 0, "read": 0,
                                        "data-skipped": 0}, [])
        self.assertIn("1 error(s), 1 warning(s)", out)
        self.assertIn("[error] resource-destroy", out)
        self.assertIn("[warning] protected-update", out)

    def test_text_shows_allowed(self):
        sup = [tc.Finding("resource-destroy", "error", "a.b", "a.b will be destroyed.")]
        out = tc.format_text([], {"create": 0, "update": 0, "delete": 1,
                                  "replace": 0, "no-op": 0, "read": 0,
                                  "data-skipped": 0}, sup)
        self.assertIn("[allowed] resource-destroy", out)
        self.assertIn("plan is clean", out)

    def test_json_shape(self):
        findings = [tc.Finding("resource-replace", "error", "a.b", "msg")]
        sup = [tc.Finding("resource-destroy", "error", "c.d", "msg2")]
        summary = {"create": 0, "update": 0, "delete": 1, "replace": 1,
                   "no-op": 0, "read": 0, "data-skipped": 0}
        out = json.loads(tc.format_json(findings, summary, sup))
        self.assertEqual(out["findings"][0]["rule"], "resource-replace")
        self.assertEqual(out["findings"][0]["severity"], "error")
        self.assertEqual(out["findings"][0]["address"], "a.b")
        self.assertEqual(out["allowed"][0]["address"], "c.d")
        self.assertEqual(out["summary"]["replace"], 1)

    def test_finding_as_dict_keys(self):
        d = tc.Finding("r", "error", "addr", "msg").as_dict()
        self.assertEqual(set(d), {"rule", "severity", "address", "message"})


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def write_plan(self, changes, name="plan.json"):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(plan(*changes), fh)
        return path

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = tc.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_clean_plan_exit_0(self):
        path = self.write_plan([rc("aws_instance.a", "aws_instance",
                                   ["create"])])
        code, out, _ = self.run_cli([path])
        self.assertEqual(code, 0)
        self.assertIn("plan is clean", out)

    def test_destroy_exit_1(self):
        path = self.write_plan([rc("aws_instance.a", "aws_instance",
                                   ["delete"])])
        code, out, _ = self.run_cli([path])
        self.assertEqual(code, 1)
        self.assertIn("resource-destroy", out)

    def test_warning_only_exit_0_by_default(self):
        path = self.write_plan([rc("aws_db_instance.m", "aws_db_instance",
                                   ["update"])])
        code, out, _ = self.run_cli([path])
        self.assertEqual(code, 0)
        self.assertIn("warning", out)

    def test_fail_on_warning_exit_1(self):
        path = self.write_plan([rc("aws_db_instance.m", "aws_db_instance",
                                   ["update"])])
        code, _, _ = self.run_cli([path, "--fail-on-warning"])
        self.assertEqual(code, 1)

    def test_bad_json_exit_2(self):
        path = os.path.join(self.dir, "bad.json")
        with open(path, "w") as fh:
            fh.write("{nope")
        code, _, err = self.run_cli([path])
        self.assertEqual(code, 2)
        self.assertIn("not valid JSON", err)

    def test_missing_file_exit_2(self):
        code, _, err = self.run_cli([os.path.join(self.dir, "missing.json")])
        self.assertEqual(code, 2)
        self.assertIn("cannot read", err)

    def test_json_format_output(self):
        path = self.write_plan([rc("aws_instance.a", "aws_instance",
                                   ["delete"])])
        code, out, _ = self.run_cli([path, "--format", "json"])
        self.assertEqual(code, 1)
        parsed = json.loads(out)
        self.assertEqual(parsed["findings"][0]["rule"], "resource-destroy")
        self.assertEqual(parsed["summary"]["delete"], 1)

    def test_allow_flag(self):
        path = self.write_plan([rc("aws_s3_bucket.old", "aws_s3_bucket",
                                   ["delete"])])
        code, out, _ = self.run_cli(
            [path, "--allow", "aws_s3_bucket.old"])
        self.assertEqual(code, 0)
        self.assertIn("[allowed]", out)

    def test_allow_file_flag(self):
        path = self.write_plan([rc("aws_s3_bucket.old", "aws_s3_bucket",
                                   ["delete"])])
        allow = os.path.join(self.dir, "allow.txt")
        with open(allow, "w") as fh:
            fh.write("aws_s3_bucket.old\n")
        code, out, _ = self.run_cli([path, "--allow-file", allow])
        self.assertEqual(code, 0)
        self.assertIn("[allowed]", out)

    def test_missing_allow_file_exit_2(self):
        path = self.write_plan([])
        code, _, err = self.run_cli(
            [path, "--allow-file", os.path.join(self.dir, "nope.txt")])
        self.assertEqual(code, 2)
        self.assertIn("allow file", err)

    def test_protect_flag_adds_type(self):
        path = self.write_plan([rc("aws_instance.a", "aws_instance",
                                   ["update"])])
        code, out, _ = self.run_cli([path, "--protect", "aws_instance"])
        self.assertEqual(code, 0)  # warning only, no --fail-on-warning
        self.assertIn("protected-update", out)

    def test_no_default_protect_flag(self):
        path = self.write_plan([rc("aws_db_instance.m", "aws_db_instance",
                                   ["update"])])
        code, out, _ = self.run_cli([path, "--no-default-protect"])
        self.assertEqual(code, 0)
        self.assertNotIn("protected-update", out)

    def test_destroy_still_flagged_with_no_default_protect(self):
        path = self.write_plan([rc("aws_db_instance.m", "aws_db_instance",
                                   ["delete"])])
        code, out, _ = self.run_cli([path, "--no-default-protect"])
        self.assertEqual(code, 1)
        self.assertIn("resource-destroy", out)

    def test_error_and_warning_together(self):
        path = self.write_plan([
            rc("aws_instance.a", "aws_instance", ["delete"]),
            rc("aws_db_instance.m", "aws_db_instance", ["update"]),
        ])
        code, out, _ = self.run_cli([path])
        self.assertEqual(code, 1)
        self.assertIn("1 error(s), 1 warning(s)", out)


if __name__ == "__main__":
    unittest.main()
