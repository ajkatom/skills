---
name: fix-repo-vulnerabilities
description: >
  Sweep every repository in the user's GitHub account for the dependency
  vulnerabilities GitHub/Dependabot flags, fix them to a clean audit, and push
  the fixes. Use this whenever the user asks to fix, clear, or clean up
  security alerts, Dependabot alerts, npm audit findings, or "the
  vulnerabilities GitHub flagged" — across their whole account, several repos,
  or a single repo — and for any scheduled/recurring vulnerability sweep.
  Strictly dependency-advisory work: not a code security review.
---

# Fix GitHub-flagged repository vulnerabilities

Drive every repository's flagged dependency vulnerabilities to zero and push
the fixes. The scope is exactly what GitHub's Dependabot alerts cover:
advisories against **committed dependency manifests and lockfiles**
(package.json, package-lock.json, yarn.lock, requirements*.txt, etc.).
Nothing else — no code review, no secret scanning, no refactoring, no README
edits. Users asking for this want their GitHub security tab clean, not a
general audit.

`npm audit` consults the same GitHub Advisory Database Dependabot uses, so a
clean `npm audit` on the committed lockfile is the ground truth that the
corresponding alerts will clear (once the fix reaches the default branch —
see "Delivering the fixes").

## 1. Enumerate and prioritize repos

1. List the account's repos (in Claude Code Remote: `list_repos`; elsewhere:
   the GitHub API/MCP tools).
2. **Skip forks** unless the user explicitly asks for them: GitHub does not
   raise Dependabot alerts on forks, and fixes to stale forks belong
   upstream. Say so in the final report rather than silently omitting them.
   A fork the user actively develops (recent pushes by them) counts as
   theirs — include it.
3. Skip repos with no dependency manifests (nothing can be flagged).
4. Classify the rest by activity, because it changes the fix policy:
   - **Active** (pushed within ~the last year): conservative fixes only —
     semver-compatible bumps and targeted overrides; run the test suite if
     one exists and it's cheap.
   - **Dormant** (older): breaking major bumps are acceptable and usually
     unavoidable; the priority is clearing the advisories, and the commit
     message must say the code was not updated to match.

Attach and shallow-clone each repo per the platform's rules (in Claude Code
Remote: `add_repo` with push access, then clone sequentially — the git proxy
throttles parallel clones).

## 2. Baseline

For every npm project directory (any `package.json` outside `node_modules` —
repos often have several: client/, server/, services/*), record
`npm audit --json` → `metadata.vulnerabilities`. This baseline goes in the
final report and the commit message.

For a manifest **without** a lockfile: `npm install --package-lock-only
--ignore-scripts` to resolve a temporary lockfile, audit that, and if fixes
are needed bump the ranges in package.json — then **delete the temporary
lockfile** before committing (don't impose a lockfile the repo deliberately
lacks).

## 3. Fix ladder (npm)

Work each project through these stages, re-auditing after every step, until
`npm audit` reports 0 or only genuinely unfixable advisories remain. Always
use `--package-lock-only` (add `--ignore-scripts` when the repo has install
scripts) so no `node_modules` is ever created.

1. **`npm audit fix --package-lock-only`** — free, semver-safe. Often clears
   most findings on old Express-era apps.
2. **`npm audit fix --force --package-lock-only`** — dormant repos only.
   Then **inspect the resulting package.json**: `--force` regularly proposes
   nonsense *downgrades* (sequelize 4→3, babel-core 6→4.x or 5.x,
   babel-preset-env→0.0.0, aws-sdk→1.x from 2011) because an ancient version
   predates the advisory. Revert those and upgrade forward by hand instead.
3. **Hand-edit package.json** for what's left, then
   `npm install --package-lock-only` (add `--legacy-peer-deps` if
   pre-existing peer conflicts block resolution):
   - Bump vulnerable **direct** deps to the patched major.
   - Add an `"overrides"` block for vulnerable **transitives** whose parents
     pin them (npm can't override a direct dep, only transitives).
4. Iterate. Small edits, re-audit each time.

### Recurring patterns (all observed in practice)

- **Babel 6 is unfixable.** babel-traverse 6 has a critical RCE
  (GHSA-67hx-6x53-jw92) with no 6.x patch. Replace babel-core /
  babel-preset-es2015 / babel-preset-react / babel-cli with the scoped
  Babel 7 equivalents (@babel/core, @babel/preset-env, @babel/preset-react,
  @babel/cli; stage presets were removed — drop them). Where Babel 6 arrives
  transitively, alias it: `"overrides": { "babel-traverse":
  "npm:@babel/traverse@^7" }`.
- **sequelize 6 pins uuid ^8** → `"overrides": { "uuid": "^11.1.1" }` clears
  GHSA-w5hq-g745-h8pq. npm's own suggestion is a downgrade to sequelize 3 —
  never take it.
- **aws-sdk v2 is blanket-flagged** (GHSA-j965-2qgj-vjmq). Only fix: replace
  with the v3 modular clients for the services the code actually imports
  (e.g. @aws-sdk/client-s3, @aws-sdk/client-polly).
- **request** is deprecated with an unpatched SSRF advisory → alias
  `"request": "npm:@cypress/request@^4"` (API-compatible fork).
- **create-react-app**: bump react-scripts to ^5.0.1, then overrides for the
  usual transitive stragglers: nth-check ^2, postcss ^8, svgo,
  webpack-dev-server, serialize-javascript, cross-spawn.
- **Old toolchains** whose successor is a rename: parcel-bundler 1 → parcel
  2; apollo-server 2/3 → @apollo/server; @nomiclabs/hardhat-waffle →
  @nomicfoundation/hardhat-ethers + hardhat-chai-matchers.
- **Truly unfixable packages** (advisory range `*`, no patched release ever —
  e.g. `speaker`): removing them means removing a feature, which is beyond
  this skill's scope. Leave them, and name them with the advisory ID in the
  commit body and the report.
- A repo with a **committed node_modules**: never modify it, never re-add it
  when staging; note in the report that GitHub also indexes vendored
  manifests, so deleting the directory (user's call) clears residual alerts.
- A **vendored library's package.json** (e.g. a jquery-ui custom build):
  its devDependencies are flagged but never installed — deleting that
  devDependencies block is the minimal honest fix.

## 4. Other ecosystems

- **pip** (`requirements*.txt`): check pinned versions and *range floors*
  against known advisories — Dependabot evaluates the minimum a range
  admits, so `pkg>=42,<50` is flagged if 42.x is vulnerable; raise the floor
  to the first clean release and keep the cap.
- **yarn.lock alongside package-lock.json**: Dependabot reads both. Mirror
  any `overrides` as a `resolutions` field and regenerate yarn.lock
  (`yarn install --ignore-scripts --ignore-engines`, then delete the created
  node_modules); verify with `yarn audit`.
- **Swift / Rust / Go**: advisory tooling may be unavailable in the sandbox;
  eyeball the pinned versions against known advisories and say in the
  report what was and wasn't checkable.

## 5. Hygiene (what a fix commit may contain)

Only manifests and lockfiles: package.json, package-lock.json, yarn.lock,
requirements*.txt. Stage files explicitly by path — never `git add -A`.
Never commit node_modules; delete any you created. Don't add .gitignore,
don't touch source code, don't "improve" anything else — mixed commits make
the security diff unreviewable.

## 6. Delivering the fixes

- Branch: `claude/fix-vulnerabilities` in each repo. If it already exists
  from a previous sweep, **update it** (merge the default branch in, add new
  fixes) rather than creating variants.
- One commit per repo (or per sweep), message format:

  ```
  fix: resolve dependency vulnerabilities flagged by GitHub

  npm audit: <crit/high/mod/low baseline> -> <final>. <If majors were
  bumped: "Major version bumps of direct dependencies were required to
  clear advisories; code has not been updated to match and may need
  changes to build."> <List any remaining advisories with IDs and why
  they are unfixable.>
  ```

- Push with `git push -u origin claude/fix-vulnerabilities`; retry network
  failures up to 4 times with exponential backoff.
- **Alerts only clear when the fix reaches the default branch.** Do not
  merge to default branches or open PRs without the user's say-so; end the
  sweep by telling the user the branches are ready and asking how they want
  them landed (or follow their standing instruction if they've given one).

## 7. Parallelize

One subagent per repo (multi-workspace repos: one agent for the whole repo)
keeps a 30-repo sweep under an hour. Give each agent the full fix ladder,
the hygiene rules, and the commit/push format; batch agents so no more than
~8-16 run at once. The orchestrator keeps score and compiles the report.

## 8. Final report

Always end with, in this order:

1. A table: repo | flagged baseline | after fix (0 or N remaining).
2. Repos with nothing to fix, with the reason (no manifests, deps clean,
   empty repo).
3. Skipped forks, one line, with the Dependabot-doesn't-flag-forks reason.
4. Unfixable advisories: package, advisory ID, why, what removing it would
   cost.
5. The caveat that dormant repos got breaking bumps and may need code
   changes to build.
6. The merge question (or confirmation of where fixes landed).
