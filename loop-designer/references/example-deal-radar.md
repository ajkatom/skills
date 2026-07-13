# Worked Example: "Deal Radar" (exercises all four loops)

A reference showing how the skill classifies a project and specializes its questions.
Use it as a pattern for binding questions to real project details.

## The project

"Deal Radar" — a feature for an existing **Next.js storefront**:
1. Add a **price-history + live-competitor-price widget** to every product page.
2. Keep competitor prices **fresh** by scraping 3 rival sites.
3. When a competitor **undercuts us by >5%**, alert the team and open a repricing issue,
   running unattended each morning.

## Classification

| Loop | Fires because |
|------|---------------|
| Turn-based | Building the widget is a discrete build-and-verify task. |
| Goal-based | Widget adds page weight; there's a measurable bar (perf / scrape accuracy). |
| Time-based | Competitor prices go stale — scraping must recur. |
| Proactive | The morning detect→alert→file-issue run should happen with no human present. |

## Specialized questions asked (note how each is bound to Deal Radar)

**Turn-based / verification**
- Widget done when: history chart renders, live competitor price shows, page still builds?
- Verify via the Playwright test for `/product/[id]`, or dev-server + screenshot the widget?
- Gates: zero new console errors on the product page; competitor price element present within 2s?

**Goal-based (`/goal`)**
- GATE: single number that says "good enough"?
- Product-page Lighthouse ≥ 90, or scrape accuracy ≥ 95% vs a hand-checked sample?
- Produced by `npm run lighthouse -- /product/demo` or `scripts/scrape-accuracy.ts`?
- Stop after 5 tries?

**Time-based (`/loop` vs `/schedule`)**
- Refresh the 3 competitor prices every 15m, hourly, or daily?
- Needs your machine on (local session/secrets) → `/loop`, or cloud so it fires with laptop closed → `/schedule`?
- Stop once all 3 sites returned fresh prices, or run indefinitely?
- Each run just update the price DB, or also open a PR when our stored price drifts?

**Proactive (`/schedule` + `/goal` + auto)**
- GATE: run the undercut→alert→issue flow unattended?
- Start each run daily at 8am, or on each fresh scrape from the time-based loop?
- Stop condition: "don't stop until every product undercut >5% today has a Slack alert AND a repricing GitHub issue"?
- Auto mode: open issues + post to Slack without asking each time? Limit = alert-only vs. draft a price-change PR (never merge)?
- Model routing: cheap model for price-diffing, capable model for real-undercut-vs-sale judgment?
- Parallelism: explore 2–3 pricing strategies in parallel worktrees with a judge, or single-track?

## Resulting artifacts

- `LOOPS.md` — all four loops + paste-ready commands.
- `goal.md` — Lighthouse ≥ 90 (or accuracy ≥ 95%), evaluator command, stop after 5.
- `.claude/skills/verify-deal-radar-widget/SKILL.md` — heavy (browser + screenshot + console gate).
- `CLAUDE.md` — pointer to the verify skill + loop conventions.
