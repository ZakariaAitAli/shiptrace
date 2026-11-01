# ADR-0001: Modular monolith with enforced import boundaries

Status: Proposed · Date: 2026-11-01

**Context.** One small service, one database, one developer. The brief requires separation of
API, application, domain and persistence with explicit boundaries.

**Decision.** One deployable with four layers, as in ARCHITECTURE §2. `import-linter`
contracts run in CI. Ports (`Protocol`) exist only at the application/persistence seam.

**Why.** A documented boundary decays; a failing build does not. The seam lets domain and use
case tests run with no database.

**Rejected.** *Microservices*: operational cost with no scaling or team need. *Hexagonal
ports everywhere*: speculative indirection. *Flat package*: faster for a week, then business
rules leak into routers.

**Consequences.** Some mapping code between ORM rows and domain types. Accepted.
