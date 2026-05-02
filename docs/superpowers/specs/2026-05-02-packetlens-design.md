# PacketLens Design

## Goal

Build a beginner-friendly Windows packet sniffer for a college networking assignment. The deliverable should be a single Python script named `packetlens.py` that uses Tkinter for the GUI and Scapy for packet capture.

## User-Facing Requirements

- Provide a simple GUI with:
  - `Start Capture` button
  - `Stop Capture` button
  - packet display table
  - status label
- Capture packets from the Wi-Fi adapter on Windows when possible.
- Automatically detect the active Wi-Fi adapter on Windows if possible.
- Fall back to Scapy's default interface if Wi-Fi detection fails.
- Show packet details in real time with these columns:
  - `Packet No`
  - `Time`
  - `Source IP`
  - `Destination IP`
  - `Protocol`
  - `Website`
- Detect HTTP traffic and extract the `Host` header when available.
- Show `N/A` when a hostname is not available.
- Stop automatically after exactly 20 displayed packets unless the user clicks Stop earlier.
- Keep the GUI responsive while capture runs.
- Disable `Start Capture` while capture is running and re-enable it after capture stops.
- Add a vertical scrollbar to the packet table.
- Show progress in the status label, for example `Captured 7 / 20 packets`.
- Include dependency instructions: `pip install scapy`
- Make it clear that the script must be run as Administrator on Windows.
- Keep the code commented and beginner-friendly.

## Architecture

The implementation stays in one file, `packetlens.py`. The file contains:

1. Small helper functions for formatting timestamps, detecting HTTP payloads, extracting HTTP hostnames, checking administrator privileges, and selecting the best Windows Wi-Fi interface.
2. A Tkinter app class that builds and manages the GUI.
3. A Scapy-based background capture worker using one asynchronous sniffing thread so the Tkinter event loop remains responsive.
4. Lightweight embedded unit tests for the helper functions so the script can still be developed and verified with a test-first workflow while remaining a single-file deliverable.

## Capture Flow

1. The user launches the script from an Administrator PowerShell or Command Prompt on Windows.
2. The app starts with Start enabled and Stop disabled.
3. When Start is clicked:
   - the app verifies that Scapy is installed
   - the app verifies Administrator privileges on Windows
   - the previous table rows are cleared
   - the packet counter resets to zero
   - the app attempts to choose a Wi-Fi-like interface on Windows
   - if that fails, the app falls back to Scapy's default interface
   - Start is disabled and Stop is enabled
   - the Scapy sniffer starts in the background
4. Every IPv4 packet is parsed and scheduled onto Tkinter's main thread for display.
5. After the twentieth displayed packet, the app stops capture automatically.
6. If the user clicks Stop earlier, capture stops and the GUI returns to idle state.

## Packet Parsing Rules

Only IPv4 packets are shown in the table so that `Source IP` and `Destination IP` are always available.

Each displayed row contains:

- `Packet No`: sequential number from 1 to 20
- `Time`: packet timestamp formatted as `HH:MM:SS`
- `Source IP`: IPv4 source address
- `Destination IP`: IPv4 destination address
- `Protocol`:
  - `HTTP` when the TCP payload looks like an HTTP request
  - `TCP` when a TCP layer exists but the payload is not recognized as HTTP
  - `IP` when there is no TCP layer
- `Website`:
  - extracted `Host` header when available
  - `N/A` otherwise

HTTP detection is intentionally simple and readable for assignment purposes. The parser checks for common HTTP request lines such as `GET`, `POST`, `HEAD`, `PUT`, `DELETE`, `OPTIONS`, `PATCH`, and `CONNECT`, then looks for a `Host:` header in the payload.

## Interface Detection Strategy

Windows adapter detection is best-effort:

- prefer working Scapy interfaces whose names or descriptions contain values like `Wi-Fi`, `wifi`, `wireless`, `wlan`, or `802.11`
- prefer interfaces that appear to have a non-loopback IPv4 address
- if no Wi-Fi-looking interface is found or an exception occurs, use Scapy's default interface

This strategy avoids hard-coding one adapter name and remains readable for beginners.

## GUI Layout

The interface stays intentionally simple:

- a title label at the top
- a button row with `Start Capture` and `Stop Capture`
- a centered packet table using `ttk.Treeview`
- a vertical scrollbar attached to the table
- a status label at the bottom

The columns use fixed widths so assignment screenshots remain tidy and readable. The Website column is wider than the others.

## Error Handling

The script should not crash when a platform-specific detail fails. Instead, it should update the status label with a readable message. Planned safeguards:

- if Scapy is missing, show an installation message
- if the script is not running as Administrator on Windows, explain that packet sniffing requires elevated privileges
- if Wi-Fi detection raises an exception, show a short status note and fall back to Scapy's default interface
- if Scapy sniffing raises an exception, stop capture cleanly and restore the button states

## Comments And Teaching Notes

The code comments should explain:

- what an IP packet contributes to the display
- why TCP is checked before attempting HTTP parsing
- why non-TCP packets are still labeled as `IP`
- why HTTPS traffic usually does not expose the website hostname in plain text inside packet payloads
- why Administrator privileges are typically required for packet sniffing on Windows

## Verification Plan

Verification should cover two levels:

1. Automated checks for the pure helper functions:
   - timestamp formatting
   - HTTP host extraction
   - Wi-Fi interface selection
2. Manual smoke check:
   - launch the GUI
   - start capture
   - confirm the table updates in real time
   - confirm progress text updates
   - confirm automatic stop at 20 packets

## Workspace Note

This workspace does not currently contain a Git repository, so the spec cannot be committed here.
