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


### Feature: Device vendor display
ID: HM-004

Description:
Show the manufacturer/vendor based on MAC address.

Acceptance criteria:
- Show vendor name when MAC address is known
- Keep fallback if vendor cannot be determined
- Display vendor next to device name or MAC

Suggested files:
- server.py
- templates/index.html


### Feature: Device summary bar
ID: HM-005

Description:
Show a summary bar at the top of the dashboard.

Acceptance criteria:
- Display total number of devices
- Display count of online devices
- Display count of idle devices
- Display count of offline devices

Suggested files:
- server.py
- templates/index.html


### Feature: Scan network button
ID: HM-006

Description:
Allow the user to trigger a manual network scan from the dashboard.

Acceptance criteria:
- Add a "Scan network" button to the UI
- Trigger backend scan when clicked
- Refresh device list after scan
- Keep implementation simple

Suggested files:
- server.py
- templates/index.html
- tests/test_server.py


### Feature: Auto-refresh dashboard
ID: HM-007

Description:
Keep the dashboard updated automatically.

Acceptance criteria:
- Refresh every 10 seconds
- A simple full-page reload is acceptable
- Must not break manual usage

Suggested files:
- templates/index.html


### Feature: Highlight new devices
ID: HM-008

Description:
Make newly discovered devices easier to spot.

Acceptance criteria:
- Mark devices first seen within the last 5 minutes
- Show a badge or highlight color
- Must be visually clear but simple

Suggested files:
- server.py
- templates/index.html


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
