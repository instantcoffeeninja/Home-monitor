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

### Feature: Device naming (manual override)
ID: HM-003

Description:
Allow setting a custom name for a device and use it consistently in the UI.

Acceptance criteria:
- Support saving a custom name per device (keyed by MAC)
- Show custom name instead of discovered hostname when present
- Fall back to discovered hostname, then IP if unavailable

Suggested files:
- src/home_monitor/app.py
- src/home_monitor/core.py
- tests/test_app.py


### Feature: Device vendor display
ID: HM-004

Description:
Display vendor information for discovered devices when available.

Acceptance criteria:
- Parse vendor from scan output when present
- Persist vendor with device record
- Show vendor on dashboard, with graceful fallback when missing

Suggested files:
- src/home_monitor/app.py
- src/home_monitor/core.py
- tests/test_app.py


### Feature: Device summary bar
ID: HM-005

Description:
Add a compact summary strip for quick status overview.

Acceptance criteria:
- Show total devices count
- Show online/idle/offline counts
- Use existing status classification where possible

Suggested files:
- src/home_monitor/app.py
- src/home_monitor/core.py
- tests/test_app.py


### Feature: Ping the found devices
ID: HM-006

Description:
Allow actively ping-checking selected discovered devices.

Acceptance criteria:
- Let users choose devices to ping
- Persist ping selection per device
- Run ping checks on selection and at regular intervals

Suggested files:
- src/home_monitor/app.py
- src/home_monitor/core.py
- tests/test_app.py


### Feature: Auto-refresh dashboard
ID: HM-007

Description:
Keep the dashboard updated without manual browser refresh.

Acceptance criteria:
- Auto-refresh dashboard every 30 seconds
- Keep implementation simple (meta refresh acceptable)
- Preserve existing controls and layout

Suggested files:
- src/home_monitor/app.py
- tests/test_app.py


### Feature: Highlight new devices
ID: HM-008

Description:
Make newly discovered devices easier to spot.

Acceptance criteria:
- Mark devices first seen within the last 5 minutes
- Show a badge or highlight color
- Must be visually clear but simple

Suggested files:
- src/home_monitor/app.py
- tests/test_app.py


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
- src/home_monitor/app.py
- src/home_monitor/core.py
- tests/test_app.py


### Feature: Export device list
ID: HM-010

Description:
Allow exporting the current device list.

Acceptance criteria:
- Export as JSON or CSV
- Include IP, MAC, last seen, and custom name if available
- Add a simple button or endpoint

Suggested files:
- src/home_monitor/app.py
- src/home_monitor/core.py
- tests/test_app.py

---

## [DONE]

_No features marked done in this reset list._
