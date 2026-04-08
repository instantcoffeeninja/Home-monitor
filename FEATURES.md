# Home Monitor Features

## [READY]

### Feature: Last seen timestamp
Description:
Show when each device was last detected.

Acceptance criteria:
- Show "online now" if seen within 60 seconds
- Otherwise show "X minutes ago" or "X hours ago"
- Display in device table

Files:
- server.py


### Feature: Device status indicator
Description:
Show visual status for each device.

Acceptance criteria:
- Green = online (< 60 sec)
- Yellow = idle (< 10 min)
- Red = offline (> 10 min)
- Display as colored dot in UI

Files:
- server.py


## [BACKLOG]

### Feature: Device naming (manual override)
Description:
Allow user to assign custom names to devices.

Acceptance criteria:
- Map MAC → name
- Persist in SQLite
- Show name instead of IP when available


### Feature: Device vendor display
Description:
Show device manufacturer based on MAC address.

Acceptance criteria:
- Extract vendor from MAC (OUI lookup)
- Show next to device name


### Feature: Device summary bar
Description:
Show total devices and status overview.

Acceptance criteria:
- Display:
  - X online
  - X idle
  - X offline
- Visible at top of dashboard


### Feature: Scan network button
Description:
Add button to trigger network scan manually.

Acceptance criteria:
- Button in UI
- Triggers backend nmap scan
- Refresh device list after scan


### Feature: Auto-refresh dashboard
Description:
Keep dashboard updated automatically.

Acceptance criteria:
- Refresh every 10 seconds
- No full page reload (simple fetch or reload ok)


### Feature: Highlight new devices
Description:
Make newly discovered devices visible.

Acceptance criteria:
- Mark devices seen for first time within last 5 minutes
- Highlight with color or badge


### Feature: Device history tracking
Description:
Store historical activity for each device.

Acceptance criteria:
- Save timestamps of detections
- Show simple history (last seen list or count)


### Feature: Export device list
Description:
Allow exporting current devices.

Acceptance criteria:
- Export as JSON or CSV
- Include IP, MAC, last seen, name


## [DONE]
