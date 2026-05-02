# PacketLens

A beginner-friendly packet sniffer built with **Python**, **Tkinter**, and **Scapy** for Windows.

PacketLens was designed as a networking assignment style application: simple to run, easy to demonstrate, and clear enough for students to explain during a presentation or lab submission.

It captures live packets, shows them in a GUI table, detects common protocols, extracts website-related information from DNS and HTTP traffic, and provides a Wireshark-style packet details panel.

## Features

- Live packet capture with a Tkinter desktop GUI
- Start and Stop controls for packet capture
- Automatic best-effort Wi-Fi adapter detection on Windows
- Fallback to Scapy's default interface if Wi-Fi detection fails
- Real-time packet table with:
  - `Packet No`
  - `Time`
  - `Source IP`
  - `Destination IP`
  - `Protocol`
  - `Website`
- Protocol detection for:
  - `DNS`
  - `HTTP`
  - `TCP`
  - `UDP`
  - `IP`
  - `ICMP`
- DNS query detection for visited domain names
- HTTP Host header extraction when available
- Packet details inspection panel with structured layer breakdown
- Protocol filter dropdown
- Search box for IP address or domain name
- Clear Filters button for quick reset during demos
- Rolling history buffer capped at 1000 packets for responsiveness
- Read-only scrollable packet details view
- Embedded unit tests in the same Python file

## Why DNS Detection Matters

Modern websites usually use **HTTPS**, which encrypts most application-layer data. That means the actual HTTP headers are often not visible in plain text.

This project solves that in a beginner-friendly way by preferring **DNS request packets** when identifying visited websites:

- If a packet is a DNS query, the app extracts the first queried domain name
- The domain is shown in lowercase
- A trailing dot is removed for display only
- The packet is labeled as `DNS`

Example:

```text
www.google.com.  ->  www.google.com
```

This makes the sniffer more useful when browsing HTTPS websites, because DNS traffic often reveals which domain was requested even when the web payload is encrypted.

## Technologies Used

- **Python 3**
- **Tkinter** for the GUI
- **Scapy** for packet capture and packet parsing
- **unittest** for built-in tests

## Requirements

Before running the project, make sure you have:

- **Windows**
- **Python 3.10+** recommended
- **Scapy** installed
- **Npcap** installed on Windows for packet capture support
- **Administrator privileges** when running the script

Tkinter is included with most standard Python installations on Windows.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/packetlens.git
cd packetlens
```

### 2. Install Python dependency

```bash
pip install scapy
```

### 3. Install Npcap

Scapy on Windows usually requires **Npcap** to capture packets.

Download and install Npcap from the official site:

- https://nmap.org/npcap/

### 4. Run the script as Administrator

Open **Command Prompt** or **PowerShell** as **Administrator**, then run:

```bash
python packetlens.py
```

## How to Run

After launching the application:

1. Click **Start Capture**
2. Generate some network traffic by opening websites or using other networked apps
3. Watch packets appear in the table in real time
4. Click a row to inspect full packet details below the table
5. Use the protocol filter and search box to narrow visible packets
6. Click **Stop Capture** when finished

## GUI Overview

The interface is intentionally simple and demonstration-friendly.

### Top controls

- **Start Capture**
  - starts live packet capture
  - disabled while capture is running

- **Stop Capture**
  - stops capture
  - enabled only while capture is running

### Filter row

- **Filter Protocol**
  - dropdown options:
    - `ALL`
    - `DNS`
    - `HTTP`
    - `TCP`
    - `UDP`
    - `IP`
    - `ICMP`

- **Search**
  - case-insensitive partial matching
  - matches:
    - source IP
    - destination IP
    - website/domain column

- **Clear Filters**
  - resets protocol filter to `ALL`
  - clears search text
  - rebuilds the visible table immediately from the rolling packet history

### Packet table

Each row shows:

- `Packet No`
- `Time`
- `Source IP`
- `Destination IP`
- `Protocol`
- `Website`

### Packet details panel

When a row is selected, the lower panel shows a structured breakdown similar to a simplified Wireshark inspection view.

Possible sections:

- `Ethernet Header`
- `IP Header`
- `TCP Header`
- `UDP Header`
- `DNS Fields`
- `HTTP Headers`

## Protocol Detection Logic

The script uses the following logic when building a packet summary:

1. If the packet contains a **DNS query**, label it as `DNS`
2. Otherwise, if it contains a visible **HTTP request payload**, label it as `HTTP`
3. Otherwise fall back to:
  - `TCP`
  - `UDP`
  - `ICMP`
  - `IP`

This keeps the output meaningful while still staying easy to explain in a classroom setting.

## Website Detection Logic

### DNS-based detection

If the packet contains a DNS question:

- extract the first query name from the DNS question section
- convert it to lowercase
- remove a trailing dot for display only
- show it in the `Website` column

Example:

```text
Packet No | Time     | Source IP    | Destination IP | Protocol | Website
1         | 12:30:15 | 192.168.1.5  | 8.8.8.8        | DNS      | google.com
```

### HTTP-based detection

If the packet is not DNS but contains a plain-text HTTP request:

- inspect the TCP payload
- detect HTTP methods such as `GET`, `POST`, `HEAD`, `PUT`, `DELETE`, `OPTIONS`, `PATCH`, `CONNECT`
- extract the `Host:` header when available

Example:

```text
2 | 12:30:16 | 192.168.1.5 | 142.250.183.78 | HTTP | google.com
```

### If no domain is available

If no domain name can be extracted, the app displays:

```text
N/A
```

## Filtering and Search

### Protocol filter

The protocol dropdown filters visible rows without stopping capture.

Only matching packets are shown in the table, but packet capture continues in the background.

### Search

The search box works together with the protocol filter.

A packet is visible only if it matches **both**:

- the currently selected protocol filter
- the current search text

Search behavior:

- case-insensitive
- partial matching
- applied only to the rolling history buffer

Examples:

- `8.8` matches `8.8.8.8`
- `google` matches `google.com`
- `192.168` matches local network addresses

### Clear Filters

The **Clear Filters** button resets the visible view quickly during demonstrations:

- protocol filter -> `ALL`
- search box -> empty
- table -> rebuilt from the rolling history buffer

## Rolling History Buffer

The project does **not** store unlimited packet history.

Instead, it keeps a rolling in-memory history buffer capped at **1000 packets**.

This design is intentional:

- helps keep the GUI responsive during long captures
- avoids unnecessary memory growth
- makes filtering and searching fast enough for classroom demos

Important behavior:

- packet numbering still reflects the **total captured packet count**
- visible rows may be trimmed from the top after the 1000-packet limit
- filtering and search rebuild the table only from the current rolling history buffer

## Packet Details Panel Behavior

The details panel is intentionally stable:

- selecting a row shows a rendered packet snapshot
- if that row later disappears because of trimming or filtering, the details panel stays unchanged
- the panel updates only when the user selects a different visible packet

This mirrors the behavior of professional packet analysis tools such as Wireshark and makes demonstrations easier to follow.

## Project Structure

This project currently keeps everything in a single file:

```text
packetlens.py
```

That file includes:

- the Tkinter GUI
- Scapy capture logic
- packet parsing helpers
- filtering and search logic
- packet details renderer
- built-in unit tests

This single-file structure makes the project easy to submit for coursework and easy to run on another machine.

## Running Tests

The project includes embedded unit tests inside `packetlens.py`.

Run them with:

```bash
python -m unittest packetlens -v
```

You can also run a syntax check:

```bash
python -m py_compile packetlens.py
```

## Typical Use Cases

This project is useful for:

- networking coursework
- packet inspection demonstrations
- DNS and HTTP traffic observation
- explaining protocol layers in class
- showing how GUI tools can be built on top of Scapy

## Limitations

This is an educational project, not a full production packet analyzer.

Known limitations:

- designed mainly for **Windows**
- relies on **Administrator privileges**
- relies on **Npcap** for capture on Windows
- shows only packets with an IPv4 layer in the main table
- HTTPS payloads are encrypted, so many website names come from DNS rather than HTTP
- rolling history is limited to 1000 packets by design
- packet detail formatting is simplified compared to Wireshark

## Troubleshooting

### `Scapy is not installed`

Install Scapy:

```bash
pip install scapy
```

### No packets appear

Check the following:

- run the terminal as **Administrator**
- make sure **Npcap** is installed
- generate real network traffic while capture is running
- verify your Wi-Fi or network adapter is active

### The app says Administrator privileges are required

Close the program, then reopen **PowerShell** or **Command Prompt** using:

- **Run as Administrator**

### Website column often shows `N/A`

That is normal for many packets.

Reasons:

- the packet may not contain a DNS query
- the packet may not contain an HTTP request
- the traffic may be encrypted
- the packet may belong to a lower network layer

## Educational Note

This project is intended for **learning, coursework, and authorized network analysis only**.

Capture and inspect traffic only on networks and systems where you have permission to do so.

## Future Improvements

Possible future additions:

- save captured packets to a file
- export visible rows to CSV
- add pause/resume capture
- add packet count statistics by protocol
- add dark mode or theme options
- support more detailed DNS response parsing
- add separate tabs for summary and raw packet bytes

## License

Add a license section here if you plan to publish the repository publicly, for example:

- MIT License
- Apache 2.0
- GPLv3

If this is only for coursework, you can replace this section with your class, semester, or submission notes.
