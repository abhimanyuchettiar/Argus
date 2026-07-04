# Contributing to Argus

Quick rules so three people can work on this without stepping on each other.

## Branches

Don't push directly to `main`. Work on your own branch:

- `feature/capture-agent` — C++ agent
- `feature/ml-pipeline` — dataset, training, inference
- `feature/db-dashboard` — schema, DB writer, API, dashboard

Keep branches short-lived — merge every few days, not every few weeks. Long-lived branches
are where merge conflicts go to breed.

## Commit Messages

```
<component>: <short summary>

<optional longer description>
```

Example:
```
agent: add flow aggregation with unordered_map

Groups packets into 1-second flow windows keyed by FlowKey
(src_ip, dst_ip, src_port, dst_port, protocol).
```

If two people pair on something, credit both:
```
git commit -m "db: design initial schema

Co-authored-by: Name <email@example.com>"
```

## Pull Requests

- Open a PR into `main` when a weekly deliverable (see README) is done.
- One other teammate should glance at it before merging — doesn't need to be deep, just
  "does this match the flow schema / does it run."
- The integration lead (Abhimanyu) does the final merge for week 6, since that's when all
  three tracks have to click together.

## The One Rule That Matters Most

If you need to change a field name/type in the flow JSON or verdict JSON
(`docs/FLOW_SCHEMA.md`), **say so in the group chat before you push it.** Two other people's
code depends on those names staying exactly as agreed.

## Weekly Sync

15 minutes, once a week: what you finished, what's blocking you, anything that needs to
change in the shared schema. This is the difference between week 6 integration taking an
afternoon vs. taking three days.
