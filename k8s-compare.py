#!/usr/bin/env python3
# k8s_compare.py — compare two Kubernetes clusters and produce apply-ready diffs.
# Copyright (C) 2026  Raúl Mahiques
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
Usage:
  python k8s_compare.py <cluster-a> <cluster-b> [--namespaces ns1,ns2] [--output-dir ./out]

cluster-a / cluster-b: kubeconfig file path OR context name in ~/.kube/config
"""

import argparse
import copy
import json
import os
import re
import subprocess
import sys
import yaml
from datetime import datetime


# Fields stripped before comparison — runtime/immutable metadata
STRIP_METADATA = {
    "resourceVersion", "uid", "creationTimestamp", "generation",
    "selfLink", "managedFields",
}

STRIP_ANNOTATIONS = {
    "kubectl.kubernetes.io/last-applied-configuration",
    "deployment.kubernetes.io/revision",
    "autoscaling.alpha.kubernetes.io/conditions",
    "autoscaling.alpha.kubernetes.io/current-replicas",
    "autoscaling.alpha.kubernetes.io/desired-replicas",
    "objectset.rio.cattle.io/applied",                # gzip+base64 applied-state blob
    "authz.cluster.auth.io/project-namespaces",       # Rancher project-scoped names
    "field.cattle.io/projectId",                      # Rancher project ID (cluster-unique)
    "field.cattle.io/creatorId",                      # Rancher creator user ID
    "listener.cattle.io/fingerprint",                 # TLS cert fingerprint (cluster-unique)
    "rancher.io/service-account.secret-ref",          # generated token secret reference
}

# Annotation key PREFIXES stripped in addition to the exact-key set above
STRIP_ANNOTATION_PREFIXES = (
    "control-plane.alpha.kubernetes.io/",
    "listener.cattle.io/",              # cn-*, ip-* keys contain hostnames or fingerprints
    "operator.cluster.x-k8s.io/",      # CAPI operator computed hashes
)

# Field names stripped recursively from any depth in the object tree
STRIP_FIELD_KEYS = {
    # Cert blobs — binary/PEM data, always cluster-unique
    "caBundle", "tls.crt", "tls.key", "ca.crt", "ca.key",
    # Cluster-unique generated IDs
    "clusterGUID", "clientID", "clientRandom",
    # Helm release timestamps (stored inside release metadata blobs)
    "firstDeployed", "lastDeployed",
    # Cluster-specific API server info (URL, CA cert) in fleet/Rancher ConfigMaps
    "apiServerURL", "apiServerCA",
    # Activity timestamps on tokens / users
    "lastUsedAt", "LastUsedAt", "lastRefresh", "LastRefresh", "lastLogin", "LastLogin",
    # Service cluster-internal IPs — always differ between clusters
    "clusterIP", "clusterIPs",
    # Secret/token credential fields
    "token",
}

# Label keys stripped from metadata.labels — their values are cluster-unique
STRIP_LABEL_KEYS = {
    "fleet.cattle.io/created-by-agent-pod",  # pod name with random suffix
    "field.cattle.io/projectId",             # Rancher project ID
    "field.cattle.io/creatorId",             # Rancher creator user ID
}

# ISO 8601 timestamp detector
_ISO8601_RE = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}')

# Standard UUID / GUID detector
_UUID_RE = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE
)

# Raw hex digests without dashes: MD5 (32), SHA1 (40), SHA256 (64) and similar
_HEX_HASH_RE = re.compile(r'^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{56}$|^[0-9a-f]{64}$', re.IGNORECASE)

# Long lowercase-alphanumeric tokens (Rancher/fleet bearer tokens, checksums, etc.)
_TOKEN_RE = re.compile(r'^[a-z0-9]{40,}$')

# Rancher/fleet generated name patterns — matched against the full resource name
_RANCHER_ID_RE = re.compile(
    r'(^|[-/:])(p|u|g)-[a-z0-9]{5,}($|[-/:])'   # p-xxxxx, u-xxxxx, g-xxxxx (any length)
    r'|'
    r'(^|[-/])c-m-[a-z0-9]{5,}($|-)'              # c-m-xxxxx cluster management IDs
    r'|'
    r'^grb-'                                        # GlobalRoleBinding resources
    r'|'
    r'(^|[-/])user-[a-z]{5}($|-)'                  # Rancher user namespace/resources (all-alpha ID)
    r'|'
    r'^request-[a-z0-9]{5}($|-)'                   # fleet ClusterRegistration request artefacts
)

# UUID anywhere in a resource name
_UUID_IN_NAME_RE = re.compile(
    r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE
)

# Long hex suffix (≥12 hex chars) — e.g. cluster-fleet-local-local-1a3d67d0a899
_HEX_SUFFIX_RE = re.compile(r'-[a-f0-9]{12,}$')

# Long base64-only strings are cert/compressed blobs — not human-comparable
_BASE64_BLOB_RE = re.compile(r'^[A-Za-z0-9+/]+=*$')

def _is_opaque_blob(value):
    return (isinstance(value, str) and len(value) >= 64
            and bool(_BASE64_BLOB_RE.match(value)))


# Populated at runtime from both clusters before comparison begins
_CLUSTER_HOSTNAMES = set()       # node names, ingress hosts, LB hostnames
_CLUSTER_GENERATED_NAMES = set() # user/role/binding names with generated suffixes


def _is_generated_name(name):
    """True if a resource name contains a cluster-generated/random component."""
    if _RANCHER_ID_RE.search(name):
        return True
    if _UUID_IN_NAME_RE.search(name):
        return True
    if _HEX_SUFFIX_RE.search(name):
        return True
    if name.startswith("sh.helm.release."):
        return True
    # 5-10 char alphanumeric suffix with at least one digit (avoids English words like 'agent')
    m = re.search(r'-([a-z0-9]{5,10})$', name)
    if m:
        suffix = m.group(1)
        if any(c.isdigit() for c in suffix):
            return True
    return False


def _looks_generated(name):
    """Alias used by collect_generated_names — broader check including all-alpha Rancher IDs."""
    return _is_generated_name(name) or bool(_RANCHER_ID_RE.search(name))

# Resource types that are purely runtime — skip entirely
SKIP_RESOURCE_TYPES = {
    "events", "endpoints", "endpointslices",
    "pods", "replicationcontrollers",
    "componentstatuses", "nodes",
    "leases", "certificatesigningrequests",
    "clusterregistrations",   # fleet agent registration state, always cluster-unique
    "csinodes",               # named after node hostnames, always cluster-unique
    "ipaddresses",            # named after IP addresses, always cluster-unique
}

# Certificate-related resource types skipped by default (each cert is unique per cluster).
# Included when --full is specified.
CERT_RESOURCE_TYPES = {
    "certificates", "certificaterequests",
    "clusterissuers", "issuers",
    "orders", "challenges",
}

# Workload types whose containers we inspect for version diffs
WORKLOAD_TYPES = {"deployments", "statefulsets", "daemonsets", "jobs", "cronjobs"}


def collect_cluster_dns(cluster):
    """Return set of node names + virtual DNS hostnames for this cluster."""
    names = set()

    out = run(kubectl(["get", "nodes", "--no-headers",
                       "-o", "custom-columns=NAME:.metadata.name"], cluster), check=False)
    for n in out.splitlines():
        n = n.strip()
        if n:
            names.add(n)

    # Ingress rule hosts
    out = run(kubectl(["get", "ingress", "--all-namespaces", "--no-headers",
                       "-o", "custom-columns=HOST:.spec.rules[*].host"], cluster), check=False)
    for n in out.splitlines():
        n = n.strip()
        if n and n != "<none>":
            names.add(n)

    # LoadBalancer external hostnames
    out = run(kubectl(
        ["get", "svc", "--all-namespaces",
         "-o", "jsonpath={range .items[?(@.spec.type==\"LoadBalancer\")]}"
               "{.status.loadBalancer.ingress[*].hostname} {end}"],
        cluster), check=False)
    for n in out.split():
        n = n.strip()
        if n:
            names.add(n)

    # Service ClusterIPs — internal IPs that appear in Settings and env vars
    out = run(kubectl(["get", "svc", "--all-namespaces",
                       "-o", "jsonpath={.items[*].spec.clusterIP}"],
                      cluster), check=False)
    for ip in out.split():
        ip = ip.strip()
        if ip and ip != "None":
            names.add(ip)

    return {n for n in names if len(n) > 4}  # skip very short tokens


def collect_generated_names(cluster):
    """Return set of resource names that have cluster-unique generated suffixes."""
    names = set()
    # Resource types whose names are commonly generated in Rancher environments
    targets = [
        "users.management.cattle.io",
        "serviceaccounts",
        "clusterrolebindings",
        "rolebindings",
        "globalrolebindings.management.cattle.io",
    ]
    for resource in targets:
        out = run(kubectl(["get", resource, "--all-namespaces", "--no-headers",
                           "-o", "custom-columns=NAME:.metadata.name"],
                          cluster), check=False)
        for n in out.splitlines():
            n = n.strip()
            if n and (_RANCHER_ID_RE.search(n) or _looks_generated(n)):
                names.add(n)
    return names


def run(cmd, check=True):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    if check and result.returncode != 0:
        print(f"ERROR running {' '.join(cmd)}:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip()


def kubectl(args, cluster):
    """Run kubectl with the given cluster spec (file path or context name)."""
    base = ["kubectl"]
    if os.path.isfile(cluster):
        base += ["--kubeconfig", cluster]
    else:
        base += ["--context", cluster]
    return base + args


def get_k8s_version(cluster):
    out = run(kubectl(["version", "--output=json"], cluster))
    data = json.loads(out)
    return data.get("serverVersion", {}).get("gitVersion", "unknown")


def get_api_resources(cluster, skip_certs=True):
    """Return list of (resource_name, namespaced) tuples."""
    out = run(kubectl(
        ["api-resources", "--verbs=list", "--output=wide", "--no-headers"],
        cluster,
    ))
    resources = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        name = parts[0].lower()
        if name in SKIP_RESOURCE_TYPES:
            continue
        if skip_certs and name in CERT_RESOURCE_TYPES:
            continue
        namespaced = parts[-2].lower() == "true"
        resources.append((name, namespaced))
    return resources


def get_objects(cluster, resource, namespaces=None):
    """Fetch all objects of a resource type; returns list of dicts."""
    if namespaces:
        objects = []
        for ns in namespaces:
            cmd = kubectl(["get", resource, "-n", ns, "-o", "json"], cluster)
            out = run(cmd, check=False)
            if not out:
                continue
            try:
                data = json.loads(out)
                objects.extend(data.get("items", []))
            except json.JSONDecodeError:
                pass
        return objects
    else:
        cmd = kubectl(["get", resource, "--all-namespaces", "-o", "json"], cluster)
        out = run(cmd, check=False)
        if not out:
            return []
        try:
            return json.loads(out).get("items", [])
        except json.JSONDecodeError:
            return []


def _deep_clean(obj):
    """Recursively strip the entire object tree by both key name and string value.

    - Keys in STRIP_FIELD_KEYS are dropped wherever they appear.
    - String values are passed through _clean_string_value; None means drop the entry.
    - List items that are cluster-unique strings are removed from the list.
    """
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if k in STRIP_FIELD_KEYS:
                continue
            if isinstance(v, str):
                cleaned = _clean_string_value(v)
                if cleaned is not None:
                    result[k] = cleaned
            elif isinstance(v, (dict, list)):
                result[k] = _deep_clean(v)
            else:
                result[k] = v
        return result
    if isinstance(obj, list):
        result = []
        for item in obj:
            if isinstance(item, str):
                cleaned = _clean_string_value(item)
                if cleaned is not None:
                    result.append(cleaned)
            elif isinstance(item, (dict, list)):
                result.append(_deep_clean(item))
            else:
                result.append(item)
        return result
    return obj


def _value_is_cluster_unique(value):
    """True if value should be dropped because it is cluster-specific."""
    if _CLUSTER_HOSTNAMES and value in _CLUSTER_HOSTNAMES:
        return True
    if _CLUSTER_GENERATED_NAMES and value in _CLUSTER_GENERATED_NAMES:
        return True
    # Values containing a known hostname (URLs, annotations, etc.)
    if _CLUSTER_HOSTNAMES:
        for h in _CLUSTER_HOSTNAMES:
            if h in value:
                return True
    # Values that ARE a Rancher-generated ID (e.g. label value "p-tvp62" or "local:p-tvp62")
    if _RANCHER_ID_RE.search(value):
        return True
    return False


def _clean_string_value(value):
    """Return None to drop the field, or a cleaned version of value.

    Drops: ISO 8601 timestamps, UUIDs, opaque base64 blobs, known cluster hostnames/names.
    For JSON-encoded strings: strips cluster-unique keys/values then re-encodes.
    """
    if not isinstance(value, str):
        return value
    if _ISO8601_RE.match(value):
        return None
    if _UUID_RE.match(value) or _HEX_HASH_RE.match(value):
        return None
    if _TOKEN_RE.match(value):
        return None
    if _is_opaque_blob(value):
        return None
    if value.startswith("-----BEGIN "):   # raw PEM certificate or key
        return None
    if _value_is_cluster_unique(value):
        return None
    if value.startswith('{'):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                cleaned = _deep_clean(parsed)
                return json.dumps(cleaned, separators=(',', ':')) if cleaned else None
        except ValueError:
            pass
    return value


def strip_runtime(obj, full=False):
    """Remove runtime/cluster-unique fields; return cleaned copy, or None to skip.

    When full=True only the truly immutable server-set fields are removed
    (resourceVersion, uid, managedFields, status, ownerReferences).  All smart
    filtering — generated-name skipping, value cleaning, annotation stripping —
    is bypassed so the caller sees the raw diff.
    """
    obj = copy.deepcopy(obj)
    meta = obj.get("metadata", {})

    for field in STRIP_METADATA:
        meta.pop(field, None)
    meta.pop("ownerReferences", None)
    obj.pop("status", None)

    if full:
        return obj

    # Skip resources whose name or namespace is cluster-generated
    name = meta.get("name", "")
    namespace = meta.get("namespace", "")
    if (meta.get("generateName")
            or _is_generated_name(name)
            or (namespace and _is_generated_name(namespace))
            or (_CLUSTER_GENERATED_NAMES and name in _CLUSTER_GENERATED_NAMES)):
        return None

    # Strip annotation keys that are always cluster-unique (not value-based)
    annotations = meta.get("annotations", {})
    for key in list(annotations.keys()):
        if key in STRIP_ANNOTATIONS or any(key.startswith(p) for p in STRIP_ANNOTATION_PREFIXES):
            del annotations[key]
    if not annotations:
        meta.pop("annotations", None)

    # Strip label keys that are always cluster-unique
    labels = meta.get("labels", {})
    for key in list(labels.keys()):
        if key in STRIP_LABEL_KEYS:
            del labels[key]
    if not labels:
        meta.pop("labels", None)

    # Recursively strip all fields by key name AND all string values by content
    return _deep_clean(obj)


def object_key(obj):
    meta = obj.get("metadata", {})
    return (
        obj.get("apiVersion", ""),
        obj.get("kind", ""),
        meta.get("namespace", ""),
        meta.get("name", ""),
    )


def collect_cluster_objects(cluster, resource_list, namespaces, full=False):
    """Return dict of key -> cleaned object for all resources on a cluster."""
    store = {}
    total = len(resource_list)
    for i, (resource, namespaced) in enumerate(resource_list, 1):
        print(f"  [{i}/{total}] fetching {resource}...", end="\r", flush=True)
        ns_list = namespaces if namespaced else None
        items = get_objects(cluster, resource, ns_list)
        for obj in items:
            cleaned = strip_runtime(obj, full=full)
            if cleaned is None:
                continue
            key = object_key(cleaned)
            store[key] = cleaned
    print()
    return store


def extract_images(obj):
    """Return set of (container_name, image) from a workload object."""
    images = set()
    spec = obj.get("spec", {})
    # Handle CronJob nesting
    if obj.get("kind") == "CronJob":
        spec = spec.get("jobTemplate", {}).get("spec", {})
    pod_spec = spec.get("template", {}).get("spec", {})
    for ctype in ("initContainers", "containers"):
        for c in pod_spec.get(ctype, []):
            images.add((c.get("name", "?"), c.get("image", "?")))
    return images


def build_version_table(objects_a, objects_b):
    """Compare container images between clusters; return list of diff rows."""
    rows = []
    all_keys = set(objects_a) | set(objects_b)
    for key in sorted(all_keys):
        api_ver, kind, namespace, name = key
        if kind.lower() not in {w.rstrip("s") for w in WORKLOAD_TYPES} and \
           kind.lower() + "s" not in WORKLOAD_TYPES:
            continue
        imgs_a = extract_images(objects_a[key]) if key in objects_a else set()
        imgs_b = extract_images(objects_b[key]) if key in objects_b else set()
        if imgs_a == imgs_b:
            continue
        all_containers = {c for c, _ in imgs_a | imgs_b}
        for container in sorted(all_containers):
            img_a = next((img for c, img in imgs_a if c == container), "—")
            img_b = next((img for c, img in imgs_b if c == container), "—")
            if img_a != img_b:
                rows.append({
                    "namespace": namespace or "(cluster-scoped)",
                    "workload_kind": kind,
                    "workload_name": name,
                    "container": container,
                    "image_cluster_a": img_a,
                    "image_cluster_b": img_b,
                })
    return rows


def field_diff(a, b):
    """Recursively return only the fields from a that differ from b."""
    if not isinstance(a, dict) or not isinstance(b, dict):
        return a
    result = {}
    for k in set(a) | set(b):
        if k not in b:
            result[k] = a[k]
        elif k not in a:
            pass  # present in b but not a — omit from a's diff
        elif isinstance(a[k], dict) and isinstance(b[k], dict):
            sub = field_diff(a[k], b[k])
            if sub:
                result[k] = sub
        elif a[k] != b[k]:
            result[k] = a[k]
    return result


def diff_objects(obj_a, obj_b):
    """Return obj_a with only differing fields, always keeping identity metadata."""
    diff = field_diff(obj_a, obj_b)
    diff["apiVersion"] = obj_a.get("apiVersion", "")
    diff["kind"] = obj_a.get("kind", "")
    meta = diff.setdefault("metadata", {})
    for field in ("name", "namespace"):
        if field in obj_a.get("metadata", {}):
            meta[field] = obj_a["metadata"][field]
    return diff


def objects_to_yaml_list(objects):
    docs = []
    for obj in sorted(objects, key=lambda o: (
        o.get("kind", ""), o.get("metadata", {}).get("namespace", ""), o.get("metadata", {}).get("name", "")
    )):
        docs.append(yaml.dump(obj, default_flow_style=False, allow_unicode=True))
    return "---\n" + "\n---\n".join(docs) if docs else ""


def main():
    parser = argparse.ArgumentParser(description="Compare two Kubernetes clusters.")
    parser.add_argument("cluster_a", help="kubeconfig file or context name for cluster A")
    parser.add_argument("cluster_b", help="kubeconfig file or context name for cluster B")
    parser.add_argument("--namespaces", help="comma-separated namespaces to compare (default: all)")
    parser.add_argument("--output-dir", default=".", help="directory for output files (default: .)")
    parser.add_argument(
        "--full",
        action="store_true",
        help="raw mode: include all resource types, bypass smart filtering, show whole objects",
    )
    args = parser.parse_args()

    namespaces = [n.strip() for n in args.namespaces.split(",")] if args.namespaces else None
    os.makedirs(args.output_dir, exist_ok=True)

    # Version check
    print("Checking Kubernetes versions...")
    ver_a = get_k8s_version(args.cluster_a)
    ver_b = get_k8s_version(args.cluster_b)
    print(f"  Cluster A: {ver_a}")
    print(f"  Cluster B: {ver_b}")
    if ver_a != ver_b:
        print(f"  WARNING: version mismatch — A={ver_a}  B={ver_b}")
    else:
        print("  Versions match.")

    # Collect cluster-specific names so they can be stripped from field values
    print("\nCollecting cluster-specific names...")
    _CLUSTER_HOSTNAMES.update(
        collect_cluster_dns(args.cluster_a) | collect_cluster_dns(args.cluster_b)
    )
    _CLUSTER_GENERATED_NAMES.update(
        collect_generated_names(args.cluster_a) | collect_generated_names(args.cluster_b)
    )
    print(f"  {len(_CLUSTER_HOSTNAMES)} hostnames, "
          f"{len(_CLUSTER_GENERATED_NAMES)} generated names collected.")

    # Discover API resources (union of both clusters)
    print("\nDiscovering API resources...")
    skip_certs = not args.full
    resources_a = get_api_resources(args.cluster_a, skip_certs=skip_certs)
    resources_b = get_api_resources(args.cluster_b, skip_certs=skip_certs)
    if skip_certs:
        print("  Certificate resources excluded (use --full to include them).")
    resource_names_a = {r for r, _ in resources_a}
    resource_names_b = {r for r, _ in resources_b}
    # Use union; namespaced flag: prefer A, fall back to B
    namespaced_map = {r: ns for r, ns in resources_b}
    namespaced_map.update({r: ns for r, ns in resources_a})
    all_resources = [(r, namespaced_map[r]) for r in sorted(resource_names_a | resource_names_b)]
    print(f"  {len(all_resources)} resource types to compare.")

    # Collect objects
    print("\nFetching objects from Cluster A...")
    objs_a = collect_cluster_objects(args.cluster_a, all_resources, namespaces, full=args.full)
    print(f"  {len(objs_a)} objects fetched.")

    print("Fetching objects from Cluster B...")
    objs_b = collect_cluster_objects(args.cluster_b, all_resources, namespaces, full=args.full)
    print(f"  {len(objs_b)} objects fetched.")

    # Diff
    print("\nComputing diffs...")
    keys_a = set(objs_a)
    keys_b = set(objs_b)

    # Objects only in A, or in both but different
    diff_a = []
    for key in keys_a:
        if key not in keys_b:
            diff_a.append(objs_a[key])
        elif objs_a[key] != objs_b[key]:
            obj = objs_a[key] if args.full else diff_objects(objs_a[key], objs_b[key])
            diff_a.append(obj)

    # Objects only in B, or in both but different
    diff_b = []
    for key in keys_b:
        if key not in keys_a:
            diff_b.append(objs_b[key])
        elif objs_a[key] != objs_b[key]:
            obj = objs_b[key] if args.full else diff_objects(objs_b[key], objs_a[key])
            diff_b.append(obj)

    print(f"  Cluster A has {len(diff_a)} differing objects.")
    print(f"  Cluster B has {len(diff_b)} differing objects.")

    # Write diff files
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_a = os.path.join(args.output_dir, f"diff_cluster_a_{ts}.yaml")
    file_b = os.path.join(args.output_dir, f"diff_cluster_b_{ts}.yaml")

    with open(file_a, "w") as f:
        f.write(objects_to_yaml_list(diff_a) or "# No differences found\n")
    with open(file_b, "w") as f:
        f.write(objects_to_yaml_list(diff_b) or "# No differences found\n")

    print(f"\nWrote: {file_a}")
    print(f"Wrote: {file_b}")

    # Version table
    version_rows = build_version_table(objs_a, objs_b)
    if version_rows or ver_a != ver_b:
        file_v = os.path.join(args.output_dir, f"version_diff_{ts}.yaml")
        report = {
            "kubernetes_versions": {
                "cluster_a": ver_a,
                "cluster_b": ver_b,
                "match": ver_a == ver_b,
            },
            "image_differences": version_rows,
        }
        with open(file_v, "w") as f:
            yaml.dump(report, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        print(f"Wrote: {file_v}  ({len(version_rows)} image version difference(s))")
    else:
        print("No version differences found — skipping version_diff file.")

    print("\nDone.")


if __name__ == "__main__":
    main()
