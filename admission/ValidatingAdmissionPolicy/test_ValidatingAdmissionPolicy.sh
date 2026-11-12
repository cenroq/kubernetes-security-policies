#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_ROOT="${ROOT}/policies"
TEST_NAMESPACE="policy-test"
TEST_LABEL_KEY="test"
TEST_LABEL_VALUE="enabled"
CLUSTER_RESOURCES_FILE="$(mktemp)"
PASSED=0
FAILED=0
SKIPPED=0

echo "Applying ValidatingAdmissionPolicies and testing examples..."

cleanup() {
  rm -f "${CLUSTER_RESOURCES_FILE}"
}

trap cleanup EXIT

apply_test_namespace() {
  cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: ${TEST_NAMESPACE}
  labels:
    ${TEST_LABEL_KEY}: ${TEST_LABEL_VALUE}
EOF
}

load_cluster_resources() {
  kubectl api-resources --namespaced=false -o name >"${CLUSTER_RESOURCES_FILE}"
}

get_policy_info() {
  python - "$1" "${CLUSTER_RESOURCES_FILE}" <<'PY'
import sys
import yaml

policy_path = sys.argv[1]
cluster_resources_path = sys.argv[2]
doc = yaml.safe_load(open(policy_path).read())
name = doc.get("metadata", {}).get("name", "")
if not name:
    raise SystemExit("missing metadata.name")

cluster_resources = set()
with open(cluster_resources_path, "r") as handle:
    for line in handle:
        value = line.strip()
        if value:
            cluster_resources.add(value)

rules = (
    doc.get("spec", {})
    .get("matchConstraints", {})
    .get("resourceRules", [])
)

is_cluster_scoped = False
for rule in rules:
    api_groups = rule.get("apiGroups", [])
    resources = rule.get("resources", [])
    if "*" in api_groups or "*" in resources:
        is_cluster_scoped = True
        break
    for resource in resources:
        resource_name = resource.split("/", 1)[0]
        for group in api_groups:
            group = group or ""
            key = f"{resource_name}.{group}" if group else resource_name
            if key in cluster_resources:
                is_cluster_scoped = True
                break
        if is_cluster_scoped:
            break
    if is_cluster_scoped:
        break

scope = "cluster" if is_cluster_scoped else "namespaced"
annotations = doc.get("metadata", {}).get("annotations") or {}
k8s_min = annotations.get("cenroq.io/kubernetes-version-min", "")
k8s_max = annotations.get("cenroq.io/kubernetes-version-max", "")
# '|' rather than a tab: bash collapses runs of whitespace separators, which would
# shift a max into the min slot whenever the min is empty.
print("|".join([name, scope, k8s_min, k8s_max]))
PY
}

# The cluster's Kubernetes minor as "major.minor". Managed offerings report the
# minor with a suffix (GKE/EKS: "30+"), so keep the digits only.
get_cluster_version() {
  kubectl version -o json | python -c '
import json, re, sys
server = json.load(sys.stdin)["serverVersion"]
print(re.sub(r"\D", "", server["major"]) + "." + re.sub(r"\D", "", server["minor"]))
'
}

# Succeeds when version $1 lies in the inclusive range [$2, $3]; an empty bound is no bound.
version_in_range() {
  python - "$1" "$2" "$3" <<'PY'
import sys

def parse(value):
    return tuple(int(part) for part in value.split("."))

version, low, high = sys.argv[1:4]
ok = (not low or parse(version) >= parse(low)) and (not high or parse(version) <= parse(high))
sys.exit(0 if ok else 1)
PY
}

create_binding_file() {
  local policy_name="$1"
  local binding_file="$2"
  local scope="$3"

  if [[ "$scope" == "cluster" ]]; then
    cat <<EOF >"$binding_file"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: ${policy_name}-test-binding
spec:
  policyName: ${policy_name}
  validationActions:
  - Deny
EOF
    return
  fi

  cat <<EOF >"$binding_file"
apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingAdmissionPolicyBinding
metadata:
  name: ${policy_name}-test-binding
spec:
  policyName: ${policy_name}
  validationActions:
  - Deny
  matchResources:
    namespaceSelector:
      matchLabels:
        ${TEST_LABEL_KEY}: ${TEST_LABEL_VALUE}
EOF
}

apply_example_precheck() {
  local scope="$1"
  local example="$2"
  if [[ "$scope" == "cluster" ]]; then
    kubectl apply --dry-run=server -f "$example" 2>&1
  else
    kubectl apply --dry-run=server -n "${TEST_NAMESPACE}" -f "$example" 2>&1
  fi
}

apply_example_manifest() {
  local scope="$1"
  local example="$2"
  if [[ "$scope" == "cluster" ]]; then
    kubectl apply -f "$example" 2>&1
  else
    kubectl apply -n "${TEST_NAMESPACE}" -f "$example" 2>&1
  fi
}

delete_example_manifest() {
  local scope="$1"
  local example="$2"
  if [[ "$scope" == "cluster" ]]; then
    kubectl delete -f "$example" >/dev/null 2>&1 || true
  else
    kubectl delete -n "${TEST_NAMESPACE}" -f "$example" >/dev/null 2>&1 || true
  fi
}

delete_resource() {
  kubectl delete -f "$1" >/dev/null 2>&1 || true
}

load_cluster_resources
apply_test_namespace
CLUSTER_VERSION="$(get_cluster_version)"
echo "Cluster Kubernetes version: ${CLUSTER_VERSION}"

while IFS= read -r policy; do
  policy_dir="$(dirname "$policy")"
  policy_id="${policy_dir#${POLICY_ROOT}/}"
  example="${policy_dir}/deny.yaml"
  policy_info="$(get_policy_info "$policy")"
  IFS='|' read -r policy_name policy_scope policy_k8s_min policy_k8s_max <<<"${policy_info}"

  if [[ -f "$example" ]]; then
    use_example="$example"
  else
    echo "⚠️  No test found for ${policy}; skipping"
    FAILED=$((FAILED + 1))
    break
  fi

  echo "---- ${policy_id} ----"
  echo "Policy:  ${policy}"
  echo "Example: ${use_example}"

  # A policy only applies to the Kubernetes minors in its cenroq.io/kubernetes-version-min
  # / -max range (inclusive, a missing bound is no bound); outside it a field it reads
  # does not exist, so the probe proves nothing.
  if ! version_in_range "${CLUSTER_VERSION}" "${policy_k8s_min}" "${policy_k8s_max}"; then
    echo "⏭️  Skipped (Kubernetes ${CLUSTER_VERSION} outside ${policy_k8s_min:-any}–${policy_k8s_max})"
    SKIPPED=$((SKIPPED + 1))
    continue
  fi

  # Skip CRD-targeted policies when their CRD is not installed (e.g. vanilla CI
  # cluster). Tests declare requirements via a "# RequiresCRD: <name>[,<name>...]"
  # comment in deny.yaml; <name> is the full CRD name (e.g. ciliumnetworkpolicies.cilium.io).
  requires_crd="$(awk -F'RequiresCRD: ' '/^# RequiresCRD: /{print $2; exit}' "$use_example")"
  if [[ -n "${requires_crd}" ]]; then
    missing_crd=""
    IFS=',' read -ra _crds <<<"${requires_crd}"
    for _crd in "${_crds[@]}"; do
      _crd="$(echo "${_crd}" | xargs)"  # trim whitespace
      [[ -z "${_crd}" ]] && continue
      if ! kubectl get crd "${_crd}" >/dev/null 2>&1; then
        missing_crd="${_crd}"
        break
      fi
    done
    if [[ -n "${missing_crd}" ]]; then
      echo "⏭️  Skipped (required CRD not installed: ${missing_crd})"
      SKIPPED=$((SKIPPED + 1))
      continue
    fi
  fi

  command_line="$(awk -F'Command: ' '/^# Command: /{print $2; exit}' "$use_example")"
  if [[ -z "${command_line}" ]]; then
    # First, ensure the manifest would be accepted without the policy (basic validity)
    set +e
    precheck_output="$(apply_example_precheck "$policy_scope" "$use_example")"
    precheck_status=$?
    set -e
    if [[ $precheck_status -ne 0 ]]; then
      echo "❌  Example is not valid without policy:"
      echo "$precheck_output"
      FAILED=$((FAILED + 1))
      break
    fi
  fi

  binding_file="$(mktemp)"
  create_binding_file "$policy_name" "$binding_file" "$policy_scope"

  kubectl apply -f "$policy"
  kubectl apply -f "$binding_file"

  sleep 2
  set +e
  if [[ -n "${command_line}" ]]; then
    echo "Applying test manifest..."
    apply_output="$(apply_example_manifest "$policy_scope" "$use_example")"
    apply_status=$?
    if [[ $apply_status -ne 0 ]]; then
      echo "❌  Failed to apply test manifest:"
      echo "$apply_output"
      FAILED=$((FAILED + 1))
      set -e
      break
    fi

    echo "Command: ${command_line}"
    output="$(eval "${command_line}" 2>&1)"
    status=$?
  else
    output="$(apply_example_precheck "$policy_scope" "$use_example")"
    status=$?
  fi
  set -e

  if [[ $status -eq 0 ]]; then
    echo "❌  Example was admitted; expected denial"
    echo "    example: ${use_example}"
    FAILED=$((FAILED + 1))
    break
  else
    echo "✅  Denied as expected"
    PASSED=$((PASSED + 1))
  fi

  # Optional companion case: a compliant manifest that must be ADMITTED while the
  # policy is active. Without this the suite can only ever prove that a policy
  # denies something, never that it leaves valid resources alone.
  allowed_example="${policy_dir}/allow.yaml"
  if [[ -f "$allowed_example" ]]; then
    echo "Allowed: ${allowed_example}"
    set +e
    allowed_output="$(apply_example_precheck "$policy_scope" "$allowed_example")"
    allowed_status=$?
    set -e
    if [[ $allowed_status -eq 0 ]]; then
      echo "✅  Admitted as expected"
      PASSED=$((PASSED + 1))
    else
      echo "❌  Compliant example was denied; expected admission"
      echo "$allowed_output"
      FAILED=$((FAILED + 1))
      break
    fi
  fi

  if [[ -n "${command_line}" ]]; then
    delete_example_manifest "$policy_scope" "$use_example"
  fi
  delete_resource "$binding_file"
  rm -f "$binding_file"
  delete_resource "$policy"
  sleep 2
done < <(find "$POLICY_ROOT" -name "policy.yaml" | sort)

echo "-------------------------------"
echo "Passed: ${PASSED}  Failed: ${FAILED}  Skipped: ${SKIPPED}"

if [[ $FAILED -ne 0 ]]; then
  exit 1
fi
