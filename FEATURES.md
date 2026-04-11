# Home Monitor Features

## Instructions for Codex
When working from this file:

1. Find the first feature under [READY]
2. Implement only that feature
3. Follow the acceptance criteria exactly
4. Keep changes minimal
5. Add or update tests if relevant
6. Do not modify unrelated features
7. When the feature is complete:
   - move it from [READY] to [DONE]
   - add today's date
   - add a short note about what was implemented

---

## [READY]


## [BACKLOG]


### Feature: Device history tracking
ID: HM-009

Description:
Store simple history for device detection.

Acceptance criteria:
- Save detection timestamps
- Show either a count or a simple recent history
- Keep database changes minimal

Suggested files:
- server.py
- home_monitor.db
- templates/index.html


### Feature: Export device list
ID: HM-010

Description:
Allow exporting the current device list.

Acceptance criteria:
- Export as JSON or CSV
- Include IP, MAC, last seen, and custom name if available
- Add a simple button or endpoint

Suggested files:
- server.py
- templates/index.html
- tests/test_server.py

---

## [DONE]

### Feature: Highlight new devices
ID: HM-008
Completed: 2026-04-11
Note: Added first-seen detection for the last 5 minutes and highlighted those rows with a simple "New" badge on the dashboard.

### Feature: Auto-refresh dashboard
ID: HM-007
Completed: 2026-04-09
Note: Added a 30-second meta refresh tag to the dashboard page head so the page auto-reloads while preserving existing manual controls.

### Feature: Ping the found devices
ID: HM-006
Completed: 2026-04-09
Note: Added per-device ping checkboxes on the dashboard, persisted ping selection on each device, triggered immediate ping on selection, and scheduled selected-device ping checks every 5 minutes with status updating through nmap_results.

### Feature: Device summary bar
ID: HM-005
Completed: 2026-04-09
Note: Added a dashboard summary bar showing total, online, idle, and offline device counts based on current status classes.

### Feature: Device vendor display
ID: HM-004
Completed: 2026-04-09
Note: Parsed vendor names from nmap MAC output, saved vendor in SQLite, and displayed vendor next to hostname with MAC fallback when vendor is unavailable.

### Feature: Device naming (manual override)
ID: HM-003
Completed: 2026-04-08
Note: Added avahi-based hostname resolution, stored custom names in a MAC-to-name SQLite table, and used overrides on dashboard/history with IP fallback.

### Feature: Device status indicator
ID: HM-002
Completed: 2026-04-08
Note: Replaced scan-streak statuses with time-based online/idle/offline logic and rendered a colored status dot next to each device hostname.

### Feature: Last seen timestamp
ID: HM-001
Completed: 2026-04-08
Note: Added human-readable last seen formatting in the device table ("online now", minutes, or hours ago) and covered it with server tests.
