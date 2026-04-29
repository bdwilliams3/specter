# Agent Guidelines

## Product Context
Specter is an AISPM platform for discovering AI-related infrastructure, shadow AI, risky workloads, and suspicious activity across Kubernetes and cloud environments.

## Current Focus
Primary development focus is Kubernetes policy, asset inventory, and detector logic under `app/detectors`.

## Jira Scope
- Work must be associated with an existing Jira `PLAN` ticket.
- Agents cannot create `PLAN` tickets.
- If there is no `PLAN` ticket associated with the requested work, stop immediately because the work is out of scope.
- Agents may create `SCRUM` and `TEST` tickets only when they are linked to the relevant `PLAN` ticket.
- Only create `SCRUM` and `TEST` tickets of the sub-task or bugfix varieties.
- Create Jira tickets sparingly. Ideally, tickets already exist and agents work from those tickets.
- Put comments describing completed work in the relevant Jira tickets.
- Never move Jira tickets to `DONE`; the user reviews and accepts the work.

## Branch Workflow
- Create a branch for changes so the user can review them.
- Keep work on the review branch until the item is moved to `DONE`.
- Merge to `main` only after the item is moved to `DONE`.

## Detector Principles
- Detect AI-related assets using multiple weak signals, not a single brittle name match.
- Treat Kubernetes labels, annotations, image names, commands, environment variables, ports, resources, and namespaces as evidence.
- Avoid hard-coding local-only cluster names or test artifacts into production rules.
- Prefer explainable findings with clear evidence fields.
- Separate asset inventory detection from threat or event detection when possible.

## Verification
- Run focused tests for changed detector behavior.
- Add or update tests when detector rules, scoring, or evidence schema changes.
- Include sample Kubernetes manifests or events in tests when practical.

## Boundaries
- Do not rewrite unrelated frontend, Helm, auth, or API code unless needed for the scoped work.
- Do not change secrets, tokens, or local cluster config.
- Do not print credentials from `.suite` or environment files.
