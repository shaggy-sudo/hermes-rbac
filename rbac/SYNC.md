# Keeping the fork in sync with upstream Hermes

This fork's `main` carries the RBAC layer on top of a snapshot of
`NousResearch/hermes-agent`, so it has diverged from upstream — a plain
fast-forward "Sync fork" won't work. Updates come in via **merge**.

## Automated (recommended)

`.github/workflows/sync-upstream.yml` runs weekly (and on manual dispatch). It
refreshes an `upstream-sync` branch from upstream `main` and opens a PR into
`main`. Review/resolve any conflicts (usually only in `hermes_cli/web_server.py`
and `hermes_cli/dashboard_auth/middleware.py` — the rest of the RBAC layer is
new files that never conflict) and merge.

Trigger manually: GitHub → Actions → "Sync upstream" → Run workflow
(or `gh workflow run sync-upstream.yml`).

Note: forks have Actions disabled by default — enable them once under the
fork's **Actions** tab.

## Manual (local)

```bash
git remote add upstream https://github.com/NousResearch/hermes-agent.git   # once
git fetch upstream main
git checkout main
git merge upstream/main      # resolve conflicts, keep the rbac/ + RBAC edits
git push origin main
```
