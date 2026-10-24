# tfplan-check

A CI guard for Terraform plans. It reads the JSON produced by
`terraform show -json <planfile>` and fails the build when the plan would
destroy or replace resources, or when it modifies a resource type you have
marked as protected (databases, buckets, queues, and other things you
cannot recreate from configuration).

Pure Python standard library. No dependencies, no network calls, works
offline in any CI runner.

## The problem

`terraform plan` output is meant to be reviewed before `apply`, but in
practice applies get approved on autopilot. The documented plan JSON
format exists precisely so tooling can review the plan instead of a human
scanning a wall of text. tfplan-check is the smallest useful version of
that gate: it parses the plan, applies a short list of rules, and exits
non-zero when the plan does something destructive, so the pipeline stops
before `apply` runs.

## Usage

```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
python3 tfplan_check.py tfplan.json
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Plan is clean (errors: none; warnings only with `--fail-on-warning` off) |
| 1 | Findings present (errors, or warnings with `--fail-on-warning`) |
| 2 | Input problem: unreadable file, invalid JSON, or not plan JSON |

Example output:

```
[error] resource-destroy: aws_s3_bucket.logs will be destroyed; aws_s3_bucket is a protected resource type.
[warning] protected-update: aws_db_instance.main (protected type aws_db_instance) will be updated in place.
plan summary: 3 to create, 1 to update, 1 to destroy, 0 to replace, 40 unchanged
tfplan-check: 1 error(s), 1 warning(s)
```

## Rules

| Rule | Severity | Trigger |
|---|---|---|
| `resource-destroy` | error | A managed resource has actions `["delete"]` |
| `resource-replace` | error | A managed resource has actions `["delete", "create"]` or `["create", "delete"]` |
| `protected-update` | warning | A resource whose type is on the protected list has actions `["update"]` |

Creates, reads, no-ops, and updates to unprotected types are normal plan
output and pass silently. Data-source entries (`mode: "data"`) are skipped.

The action semantics come straight from HashiCorp's documented plan JSON
format: a replacement is represented as `["delete", "create"]` or
`["create", "delete"]`, and any action list containing `delete` means the
object will be deleted.

## Options

```
--protect TYPE            add a resource type to the protected list (repeatable)
--no-default-protect      ignore the built-in protected list
--allow ADDRESS           suppress findings for one exact resource address (repeatable)
--allow-file PATH         file of allowed addresses, one per line, # comments
--fail-on-warning         exit 1 when only warnings are present
--format text|json        output format (default: text)
```

`--allow` addresses must match Terraform's address exactly, including
module prefixes, e.g. `module.vpc.aws_s3_bucket.logs`. Allowed findings
are still printed, marked `[allowed]`, so the review trail is visible.

## The built-in protected list

The default list covers common stateful resource types across AWS, Google
Cloud, Azure, and Kubernetes (RDS, S3, DynamoDB, EBS, Cloud SQL, Cloud
Storage, Cosmos DB, persistent volumes, and similar). It is a heuristic,
not a taxonomy: tune it with `--protect` / `--no-default-protect` for your
own estate. Destroy and replace findings apply to every resource type
regardless of the protected list.

## Caveats

- Input must be `terraform show -json <planfile>` output. A saved text
  plan or `terraform plan` stdout will be rejected with exit 2.
- This is a policy gate, not a security scanner: it checks what the plan
  will do, not whether the configuration is safe.
- Unknown `change.actions` values are rejected (exit 2) rather than
  silently ignored, so a future Terraform action type cannot slip past
  the guard.

## Source

- HashiCorp, Terraform JSON output format (resource_changes,
  change.actions, replace semantics):
  https://developer.hashicorp.com/terraform/internals/json-format

## Development

53 tests, all fabricated plan JSON fixtures, no Terraform required:

```bash
python3 -m unittest -v
```

CI runs the suite on Ubuntu and Windows with Python 3.9 and 3.13.

## License

MIT - see LICENSE.
