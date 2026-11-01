# ADR-0011: Readiness and schema compatibility

Status: Proposed · Date: 2026-11-01

**Context.** `/readyz` compares the database revision with the revisions this build knows. It must
stay ready during expand/contract rollouts, and refuse a schema the build cannot use.

| Database revision, as seen by a build | Today | Correct? |
|---|---|---|
| Equals this build's head | Ready | Yes |
| Known, older than head | Not ready | Yes: migrate first |
| Empty, missing or several rows | Not ready | Yes |
| Unknown, newer after an expand migration | Ready | Yes: old release keeps serving |
| Unknown, newer after a **contract** migration | Ready | **No**: columns this build uses are gone |
| Unknown, because revision files were pruned | Ready | **No**: prevented by a rule, not by code |

The two wrong rows are one flaw: a revision ID says nothing about compatibility, so "unknown" cannot
mean "safe". An old release rolled back past a contract migration reports ready and fails on every
real request. No such migration exists yet, so nothing is exposed today.

**Decision.**
1. Keep today's logic for P0 and P1, which have only expand migrations.
2. Before the first contract migration, add a one-row `schema_compatibility` table holding
   `minimum_build_revision`, the oldest revision a build must know. Only contract migrations raise
   it. An unknown revision is then ready only if this build knows `minimum_build_revision`.
3. Until that exists, contract migrations and pruning revision files are forbidden, a rule that
   `migration-reviewer` enforces.
4. Rollback after a contract migration is restore-from-backup or roll forward, never redeploying
   the old image. The Phase 7 rollback design must state this.

5. `minimum_build_revision` must be the newest revision the **previous** release cannot run on, and
   must stay known to the release being rolled out. Setting it to the contract revision itself
   would drain the serving release mid-rollout.

**Limit of the fix.** Only builds containing step 2 can read the table. Any image built before it
stays ready on an incompatible schema, permanently. So rollback across the release that introduces
step 2 stays unprotected, and rule 4 covers it. Step 2 also changes AC16, whose wording says unknown
means newer, so it needs a spec change.

**Why not build it now.** It would be an unused table with one row and no migration to exercise it.
The rule costs nothing while no contract migration is needed, and the design is cheap to add first.

**Rejected.**
- *Treat unknown as not ready*: breaks expand/contract, since old tasks would drain as soon as the
  migration runs, which is the outage the pattern exists to avoid.
- *Ship every revision ID in a manifest*: an old build cannot know future revisions, by definition.
- *Compare numeric schema versions*: only restates "newer", and says nothing about compatibility.
- *Run migrations at startup*: races between tasks, and hides the problem instead of detecting it.

**Consequences.** Readiness cannot detect a contract rollback until step 2 lands, and never can for
older images. The plan holds step 2 as a standing obligation. `/readyz` checks
compatibility only; it never proves that queries work. Whether the load balancer should use it at
all during a database outage stays open for Phase 7.
