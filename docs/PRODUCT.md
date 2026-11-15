# Product brief: SELinux Lens

## Mission

Make SELinux denial investigation understandable and auditable on Fedora GNOME while preserving the protections SELinux provides. Convert raw events into an exploration workflow, not a one-click bypass tool.

## Audience

Fedora GNOME developers diagnosing their own services; students learning SELinux, audit and MAC; local administrators; security researchers doing authorized investigation. Assume users might be learning the difference between a policy denial, actual block and application failure.

## Core questions

1. What process, source context, object, target context, class and operation are in the event?
2. Is the AVC recorded in enforcing or permissive context, or is that unknown?
3. What further data would support or rule out suspected causes?
4. How can the user export an evidence-linked investigation without casually leaking private paths?

## v0.1 user journey

Open app -> see mode/collection status -> search recent denials -> select event -> see observed facts, conditional hypotheses, checks and raw text -> optionally export redacted JSON. When audit logs are inaccessible, show an explicit message and offer --demo rather than requesting an elevated GUI.

## Longer-term user experience

- Dashboard with SELinux state, coverage/limitations, filtered event counts and recent trends.
- Investigation workspace grouping records by audit serial, service and timeline.
- Context explorer for process and file labels, default contexts and policy booleans.
- Evidence navigator showing the source and reliability of each conclusion.
- Guided *review* of possible changes with impact/confidence and no implicit application.
- Search and case history with opt-in, local encryption/retention policy where justified.
- Export of precise, shareable, redactable reports.
- Native GNOME design with keyboard-first accessibility.

## Non-goals

Vulnerability detection; attack attribution; magical root-cause certainty; disabling SELinux; installing policies on the user's behalf; escalating the whole GUI; cloud accounts; silent background monitoring; blanket 'allow' suggestions; replacing auditd or SELinux itself.

## Success metrics

v0.1: a user can launch fictional demo, inspect three coherent examples, view accurate enforcing/permissive semantics, query recent logs if allowed, recover gracefully when not allowed and export a valid redacted report. Future: deterministic correlation tests; Polkit helper security tests; Fedora GUI acceptance run; measurable reduction in investigation steps without unsafe advice.

## UX language

Always label 'Observed', 'Possible explanation' and 'Next check'. A suggestion is not a confirmed diagnosis. No unexplained severity score derived from raw AVC count. Distinguish 'No recent events' from 'Cannot read audit logs', and never represent 'unknown' as 'enforcing'. For large logs, preserve responsive UI and bound resource usage.
