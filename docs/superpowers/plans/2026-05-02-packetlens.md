# PacketLens Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single-file Tkinter and Scapy packet sniffer for Windows that shows live IPv4 packets in a clean table with a beginner-friendly inspection workflow.

**Architecture:** Keep everything in `packetlens.py`. Use small pure helper functions for parsing and interface selection, then a Tkinter app class that starts one background Scapy sniffing thread with GUI updates scheduled back onto Tkinter's main thread.

**Tech Stack:** Python 3, Tkinter, Scapy, unittest

---

### Task 1: Create The Single-File TDD Harness

**Files:**
- Create: `packetlens.py`
- Test: `packetlens.py`

- [ ] **Step 1: Write the failing tests inside `packetlens.py`**

```python
class HelperFunctionTests(unittest.TestCase):
    def test_extracts_http_host_from_request(self):
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"Host: google.com\r\n"
            b"User-Agent: Test\r\n\r\n"
        )
        is_http, host = inspect_http_payload(payload)
        self.assertTrue(is_http)
        self.assertEqual(host, "google.com")

    def test_returns_none_for_non_http_payload(self):
        is_http, host = inspect_http_payload(b"\x16\x03\x01\x02\x00")
        self.assertFalse(is_http)
        self.assertIsNone(host)

    def test_formats_timestamp_as_clock_time(self):
        formatted = format_packet_timestamp(1700000000.0)
        self.assertRegex(formatted, r"^\d{2}:\d{2}:\d{2}$")

    def test_selects_wifi_interface_from_windows_names(self):
        interfaces = [
            {"name": "Ethernet", "description": "Ethernet Adapter", "ip": "10.0.0.8"},
            {"name": "Intel Wireless", "description": "Wi-Fi", "ip": "192.168.1.20"},
        ]
        selected = choose_windows_wifi_interface(interfaces, default_iface="default")
        self.assertEqual(selected, interfaces[1])
```

- [ ] **Step 2: Run the tests to verify the red phase**

Run: `python -m unittest packetlens -v`
Expected: FAIL because helper functions are not implemented yet.

- [ ] **Step 3: Commit the test-first harness if git is available**

```bash
git add packetlens.py
git commit -m "test: add packet sniffer helper tests"
```

If the workspace is not a git repository, skip the commit and continue.

### Task 2: Implement Helper Functions And Runtime Guards

**Files:**
- Modify: `packetlens.py`
- Test: `packetlens.py`

- [ ] **Step 1: Add the helper functions with the smallest code needed to satisfy the tests**

```python
def format_packet_timestamp(timestamp_value: float) -> str:
    return datetime.fromtimestamp(float(timestamp_value)).strftime("%H:%M:%S")


def inspect_http_payload(payload: bytes) -> tuple[bool, str | None]:
    text = payload.decode("utf-8", errors="ignore")
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or not any(lines[0].startswith(method) for method in HTTP_METHODS):
        return False, None

    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            return True, host or None

    return True, None


def choose_windows_wifi_interface(interfaces, default_iface=None):
    ...
```

- [ ] **Step 2: Add the runtime guards that keep the GUI from crashing**

```python
try:
    from scapy.all import AsyncSniffer, IP, Raw, TCP, conf
    from scapy.interfaces import get_working_ifaces
    SCAPY_AVAILABLE = True
except ImportError:
    AsyncSniffer = IP = Raw = TCP = conf = None
    get_working_ifaces = None
    SCAPY_AVAILABLE = False


def is_running_as_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False
```

- [ ] **Step 3: Run the tests to verify green**

Run: `python -m unittest packetlens -v`
Expected: PASS for the helper tests.

- [ ] **Step 4: Commit the helper implementation if git is available**

```bash
git add packetlens.py
git commit -m "feat: add packet parsing helpers"
```

If the workspace is not a git repository, skip the commit and continue.

### Task 3: Build The Tkinter GUI And Scapy Capture Flow

**Files:**
- Modify: `packetlens.py`
- Test: `packetlens.py`

- [ ] **Step 1: Add a packet summary model and the packet-to-row parser**

```python
@dataclass
class PacketSummary:
    packet_no: int
    time_text: str
    source_ip: str
    destination_ip: str
    protocol: str
    website: str


def build_packet_summary(packet_number: int, packet) -> PacketSummary | None:
    if not SCAPY_AVAILABLE or IP not in packet:
        return None

    ip_layer = packet[IP]
    payload = bytes(packet[Raw].load) if TCP in packet and Raw in packet else b""
    is_http, host = inspect_http_payload(payload)
    protocol = "HTTP" if is_http else "TCP" if TCP in packet else "IP"
    website = host if host else "N/A"

    return PacketSummary(
        packet_no=packet_number,
        time_text=format_packet_timestamp(packet.time),
        source_ip=ip_layer.src,
        destination_ip=ip_layer.dst,
        protocol=protocol,
        website=website,
    )
```

- [ ] **Step 2: Add the Tkinter app class and widgets**

```python
class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.packet_count = 0
        self.max_packets = 20
        self.capturing = False
        self.sniffer = None
        self.packet_lock = threading.Lock()
        self.status_var = tk.StringVar(value="Ready. Run as Administrator on Windows.")
        self._build_widgets()
```

- [ ] **Step 3: Add start, stop, and packet callback behavior**

```python
def start_capture(self):
    ...
    self.sniffer = AsyncSniffer(
        iface=selected_iface,
        store=False,
        prn=self._handle_packet,
        lfilter=lambda packet: IP in packet,
    )
    self.sniffer.start()


def _handle_packet(self, packet):
    ...
    self.root.after(0, lambda: self._append_packet_row(summary))


def stop_capture(self, auto_stop=False):
    ...
```

- [ ] **Step 4: Run the embedded tests again**

Run: `python -m unittest packetlens -v`
Expected: PASS

- [ ] **Step 5: Run a syntax-only check**

Run: `python -m py_compile packetlens.py`
Expected: no output and exit code 0

- [ ] **Step 6: Commit the GUI feature if git is available**

```bash
git add packetlens.py
git commit -m "feat: add PacketLens GUI"
```

If the workspace is not a git repository, skip the commit and continue.

### Task 4: Manual Windows Smoke Check

**Files:**
- Verify: `packetlens.py`

- [ ] **Step 1: Launch the GUI from an Administrator terminal**

Run: `python packetlens.py`
Expected: the window opens with Start enabled, Stop disabled, and a scrollable table.

- [ ] **Step 2: Start capture and generate some network traffic**

Run: browse a few websites while capture is running
Expected: rows appear in real time, progress updates as `Captured N / 20 packets`, and Website shows either the HTTP host or `N/A`.

- [ ] **Step 3: Verify automatic stop**

Run: allow capture to continue
Expected: capture stops at exactly 20 displayed packets and Start becomes enabled again.

- [ ] **Step 4: Verify manual stop**

Run: start again and click `Stop Capture` before 20 packets
Expected: capture stops early and the status label reports the smaller count.

- [ ] **Step 5: Commit verification notes if git is available**

```bash
git add packetlens.py
git commit -m "docs: verify packet sniffer behavior"
```

If the workspace is not a git repository, skip the commit and continue.
