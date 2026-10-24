#!/usr/bin/env python3
"""tfplan-check - CI guard for Terraform plan JSON.

Reads the JSON produced by `terraform show -json <planfile>` and fails the
build when the plan would destroy or replace resources, or touch resource
types you marked as protected. Pure standard library; works with any
Terraform version whose plan JSON follows HashiCorp's documented format.

Plan JSON format reference:
https://developer.hashicorp.com/terraform/internals/json-format
"""

import argparse
import json
import sys

# Valid change.actions tuples per the HashiCorp JSON format docs. The two
# two-element forms are replacements; any tuple containing "delete" means
# the object will be deleted.
KNOWN_ACTIONS = {
    ("no-op",),
    ("create",),
    ("read",),
    ("update",),
    ("delete",),
    ("delete", "create"),
    ("create", "delete"),
}

# Resource types that usually hold state you cannot recreate from config.
# A heuristic default list: extend with --protect, disable with
# --no-default-protect.
DEFAULT_PROTECTED_TYPES = frozenset([
    "aws_db_instance",
    "aws_rds_cluster",
    "aws_rds_cluster_instance",
    "aws_s3_bucket",
    "aws_dynamodb_table",
    "aws_ebs_volume",
    "aws_efs_file_system",
    "aws_elasticache_cluster",
    "aws_redshift_cluster",
    "aws_kinesis_stream",
    "aws_sqs_queue",
    "google_sql_database_instance",
    "google_storage_bucket",
    "google_bigquery_dataset",
    "google_pubsub_topic",
    "google_redis_instance",
    "azurerm_mssql_server",
    "azurerm_mssql_database",
    "azurerm_postgresql_server",
    "azurerm_mysql_server",
    "azurerm_storage_account",
    "azurerm_cosmosdb_account",
    "azurerm_redis_cache",
    "azurerm_servicebus_namespace",
    "kubernetes_persistent_volume",
    "kubernetes_persistent_volume_claim",
])


class PlanError(Exception):
    """Raised for unreadable or structurally invalid plan input (exit 2)."""


class Finding:
    def __init__(self, rule, severity, address, message):
        self.rule = rule
        self.severity = severity  # "error" or "warning"
        self.address = address
        self.message = message

    def as_dict(self):
        return {
            "rule": self.rule,
            "severity": self.severity,
            "address": self.address,
            "message": self.message,
        }


def load_plan(path):
    """Load and structurally validate a plan JSON file."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise PlanError("cannot read %s: %s" % (path, exc))
    try:
        plan = json.loads(text)
    except ValueError as exc:
        raise PlanError(
            "%s is not valid JSON: %s. Generate plan JSON with "
            "`terraform show -json <planfile>`." % (path, exc)
        )
    if not isinstance(plan, dict):
        raise PlanError("%s: top level of plan JSON must be an object." % path)
    if "resource_changes" not in plan:
        raise PlanError(
            "%s has no 'resource_changes' key. This does not look like "
            "`terraform show -json <planfile>` output." % path
        )
    if not isinstance(plan["resource_changes"], list):
        raise PlanError("%s: 'resource_changes' must be a list." % path)
    return plan


def load_allow_file(path):
    """Read allowed addresses from a file: one per line, # comments."""
    allowed = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.split("#", 1)[0].strip()
                if line:
                    allowed.append(line)
    except OSError as exc:
        raise PlanError("cannot read allow file %s: %s" % (path, exc))
    return allowed


def _is_replace(actions):
    return "delete" in actions and "create" in actions


def _is_destroy(actions):
    return actions == ("delete",)


def check_plan(plan, protected_types, allowed):
    """Evaluate resource_changes. Returns (findings, summary, suppressed)."""
    findings = []
    suppressed = []  # findings dropped by the allow list
    summary = {
        "create": 0,
        "update": 0,
        "delete": 0,
        "replace": 0,
        "no-op": 0,
        "read": 0,
        "data-skipped": 0,
    }
    allowed = set(allowed)

    def emit(finding):
        if finding.address in allowed:
            suppressed.append(finding)
        else:
            findings.append(finding)

    for i, rc in enumerate(plan["resource_changes"]):
        if not isinstance(rc, dict):
            raise PlanError("resource_changes[%d] is not an object." % i)
        address = rc.get("address")
        rtype = rc.get("type")
        mode = rc.get("mode", "managed")
        change = rc.get("change")
        if mode == "data":
            summary["data-skipped"] += 1
            continue
        if not isinstance(address, str) or not address:
            raise PlanError(
                "resource_changes[%d] is missing a string 'address'." % i)
        if not isinstance(change, dict) or "actions" not in change:
            raise PlanError(
                "%s: missing 'change.actions'." % address)
        actions = change["actions"]
        if not isinstance(actions, list) or not all(
                isinstance(a, str) for a in actions):
            raise PlanError(
                "%s: 'change.actions' must be a list of strings." % address)
        actions = tuple(actions)
        if actions not in KNOWN_ACTIONS:
            raise PlanError(
                "%s: unknown change.actions %s; this tool knows the actions "
                "documented in HashiCorp's plan JSON format." % (
                    address, json.dumps(list(actions))))

        if actions == ("no-op",):
            summary["no-op"] += 1
            continue
        if actions == ("read",):
            summary["read"] += 1
            continue
        if actions == ("create",):
            summary["create"] += 1
            continue

        protected = rtype in protected_types
        if _is_replace(actions):
            summary["replace"] += 1
            emit(Finding(
                "resource-replace", "error", address,
                "%s will be replaced (destroyed and recreated)%s." % (
                    address,
                    "; %s is a protected resource type" % rtype
                    if protected else "")))
        elif _is_destroy(actions):
            summary["delete"] += 1
            emit(Finding(
                "resource-destroy", "error", address,
                "%s will be destroyed%s." % (
                    address,
                    "; %s is a protected resource type" % rtype
                    if protected else "")))
        elif actions == ("update",):
            summary["update"] += 1
            if protected:
                emit(Finding(
                    "protected-update", "warning", address,
                    "%s (protected type %s) will be updated in place." % (
                        address, rtype)))
    return findings, summary, suppressed


def format_text(findings, summary, suppressed):
    lines = []
    errors = sum(1 for f in findings if f.severity == "error")
    warnings = sum(1 for f in findings if f.severity == "warning")
    for f in findings:
        lines.append("[%s] %s: %s" % (f.severity, f.rule, f.message))
    for f in suppressed:
        lines.append("[allowed] %s: %s" % (f.rule, f.message))
    lines.append(
        "plan summary: %d to create, %d to update, %d to destroy, "
        "%d to replace, %d unchanged" % (
            summary["create"], summary["update"], summary["delete"],
            summary["replace"], summary["no-op"]))
    if findings:
        lines.append("tfplan-check: %d error(s), %d warning(s)" % (
            errors, warnings))
    else:
        lines.append("tfplan-check: plan is clean")
    return "\n".join(lines)


def format_json(findings, summary, suppressed):
    return json.dumps({
        "findings": [f.as_dict() for f in findings],
        "allowed": [f.as_dict() for f in suppressed],
        "summary": summary,
    }, indent=2)


def build_parser():
    p = argparse.ArgumentParser(
        prog="tfplan-check",
        description="Fail CI when a Terraform plan destroys, replaces, or "
                    "modifies protected resources. Input is the output of "
                    "`terraform show -json <planfile>`.")
    p.add_argument("plan", help="path to plan JSON "
                                "(terraform show -json output)")
    p.add_argument("--protect", action="append", default=[],
                   metavar="TYPE",
                   help="add a resource type to the protected list "
                        "(repeatable)")
    p.add_argument("--no-default-protect", action="store_true",
                   help="start from an empty protected list instead of the "
                        "built-in stateful-resource defaults")
    p.add_argument("--allow", action="append", default=[],
                   metavar="ADDRESS",
                   help="allow findings for an exact resource address, e.g. "
                        "aws_s3_bucket.logs (repeatable)")
    p.add_argument("--allow-file", metavar="PATH",
                   help="file with allowed addresses, one per line, "
                        "# comments")
    p.add_argument("--fail-on-warning", action="store_true",
                   help="exit 1 when only warnings are present")
    p.add_argument("--format", choices=["text", "json"], default="text",
                   help="output format (default: text)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        plan = load_plan(args.plan)
        allowed = list(args.allow)
        if args.allow_file:
            allowed.extend(load_allow_file(args.allow_file))
    except PlanError as exc:
        print("tfplan-check: %s" % exc, file=sys.stderr)
        return 2

    protected = set() if args.no_default_protect else set(
        DEFAULT_PROTECTED_TYPES)
    protected.update(args.protect)

    try:
        findings, summary, suppressed = check_plan(plan, protected, allowed)
    except PlanError as exc:
        print("tfplan-check: %s" % exc, file=sys.stderr)
        return 2

    if args.format == "json":
        print(format_json(findings, summary, suppressed))
    else:
        print(format_text(findings, summary, suppressed))

    if any(f.severity == "error" for f in findings):
        return 1
    if args.fail_on_warning and findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
