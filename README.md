# k8s-compare

Compare two Kubernetes clusters and produce apply-ready YAML diffs.

## Requirements

- Python 3.6+
- `pyyaml` (`pip install pyyaml`)
- `kubectl` in PATH with access to both clusters

## Usage

```bash
python k8s-compare.py <cluster-a> <cluster-b> [options]
```

`cluster-a` and `cluster-b` can be:
- A **context name** from `~/.kube/config`
- A **kubeconfig file path**

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--namespaces ns1,ns2` | all | Limit comparison to specific namespaces |
| `--output-dir ./out` | `.` | Directory to write output files |
| `--full` | off | Include certificate resources; output whole objects instead of field-level diffs |

### Examples

```bash
# Compare two contexts
python k8s-compare.py prod staging

# Compare using separate kubeconfig files
python k8s-compare.py /path/kubeconfig-a.yaml /path/kubeconfig-b.yaml

# Limit to specific namespaces and write results to a folder
python k8s-compare.py prod staging --namespaces default,kube-system --output-dir ./results
```

## Output files

All files are timestamped (`_YYYYMMDD_HHMMSS`).

| File | Contents |
|------|----------|
| `diff_cluster_a_<ts>.yaml` | Objects unique to or different on cluster A — ready to `kubectl apply` |
| `diff_cluster_b_<ts>.yaml` | Objects unique to or different on cluster B — ready to `kubectl apply` |
| `version_diff_<ts>.yaml` | K8s version comparison + table of container image differences per workload |

The `version_diff` file is only created when a version or image difference is detected.

## Default vs --full mode

| Behaviour | Default | `--full` |
|-----------|---------|----------|
| Diff output | Only the differing fields (+ identity metadata) | Whole object |
| Certificate resources | Skipped | Included |

Objects that exist on only one cluster are always output in full regardless of mode.

## What is compared

All API resource types supported by both clusters are compared, except purely runtime types:

- Skipped entirely: `pods`, `events`, `nodes`, `endpoints`, `endpointslices`, `leases`, and other ephemeral resources
- Stripped before comparison: `status`, `uid`, `resourceVersion`, `creationTimestamp`, `generation`, `managedFields`, `ownerReferences`, and controller-injected annotations

This ensures the output contains only fields you can actually set when applying to another cluster.

## Version diffing

For workloads (Deployments, StatefulSets, DaemonSets, Jobs, CronJobs), the script compares container images between both clusters and lists any mismatches in `version_diff_<ts>.yaml`:

```yaml
kubernetes_versions:
  cluster_a: v1.29.3
  cluster_b: v1.28.7
  match: false

image_differences:
  - namespace: default
    workload_kind: Deployment
    workload_name: my-app
    container: my-app
    image_cluster_a: my-app:v2.1.0
    image_cluster_b: my-app:v2.0.5
```
