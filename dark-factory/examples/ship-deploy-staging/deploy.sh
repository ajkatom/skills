#!/usr/bin/env bash
# Stub deploy script for the ship-deploy-staging example. Real deploy scripts
# take the operator's argv and do the real thing (kubectl/flyctl/terraform/...);
# this stub only ECHOES so the example is safe to run. It reads a brokered token
# from the environment (resolved host-side by df_creds at action time) WITHOUT
# printing its value — the value reaches only this process's env, never a log.
set -euo pipefail

mode="${1:---deploy}"
if [[ -z "${STAGING_DEPLOY_TOKEN:-}" ]]; then
  echo "deploy.sh: STAGING_DEPLOY_TOKEN not set in the environment" >&2
  exit 1
fi

case "$mode" in
  --deploy)
    # cwd is the materialized, re-verified sealed artifact.
    echo "deploy.sh: deploying $(ls -1 | wc -l | tr -d ' ') files to staging (token present)"
    ;;
  --rollback)
    echo "deploy.sh: rolling back the staging deploy"
    ;;
  *)
    echo "deploy.sh: unknown mode $mode" >&2
    exit 2
    ;;
esac
