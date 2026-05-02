"""PacketLens: a simple packet sniffer GUI for a college networking assignment.

Install dependency:
    pip install scapy

Run on Windows from an Administrator terminal:
    python packetlens.py

Scapy on Windows usually needs Npcap installed in addition to the Python package.
"""

from __future__ import annotations

import ctypes
import os
import threading
import tkinter as tk
import unittest
from dataclasses import dataclass
from datetime import datetime
from tkinter import ttk
from typing import Any

try:
    from scapy.all import AsyncSniffer, DNS, Ether, ICMP, IP, Raw, TCP, UDP, conf
    from scapy.interfaces import get_working_ifaces

    SCAPY_AVAILABLE = True
except ImportError:
    AsyncSniffer = None
    DNS = None
    Ether = None
    ICMP = None
    IP = None
    Raw = None
    TCP = None
    UDP = None
    conf = None
    get_working_ifaces = None
    SCAPY_AVAILABLE = False


MAX_VISIBLE_ROWS = 1000
FILTER_PROTOCOL_OPTIONS = ("ALL", "DNS", "HTTP", "TCP", "UDP", "IP", "ICMP")
HTTP_METHODS = (
    "GET ",
    "POST ",
    "HEAD ",
    "PUT ",
    "DELETE ",
    "OPTIONS ",
    "PATCH ",
    "CONNECT ",
)


@dataclass
class PacketSummary:
    """Small data object for one row in the packet table."""

    packet_no: int
    time_text: str
    source_ip: str
    destination_ip: str
    protocol: str
    website: str


@dataclass
class PacketRecord:
    """One rolling-history entry used to rebuild the filtered table."""

    summary: PacketSummary
    packet: Any


def format_packet_timestamp(timestamp_value: float) -> str:
    """Convert a packet timestamp into a readable HH:MM:SS clock value."""

    return datetime.fromtimestamp(float(timestamp_value)).strftime("%H:%M:%S")


def format_capture_status(packet_count: int) -> str:
    """Build the live status label text for the total captured packet count."""

    return f"Captured: {packet_count} packets"


def format_dns_query_name_for_display(query_name: Any) -> str | None:
    """Normalize a DNS query name for the Website column display."""

    if query_name is None:
        return None

    if isinstance(query_name, bytes):
        display_name = query_name.decode("utf-8", errors="ignore")
    else:
        display_name = str(query_name)

    display_name = display_name.strip().lower()
    if not display_name:
        return None

    return display_name[:-1] if display_name.endswith(".") else display_name


def inspect_http_payload(payload: bytes) -> tuple[bool, str | None]:
    """Return whether the payload looks like HTTP and its Host header if present."""

    if not payload:
        return False, None

    # HTTP headers are plain text, so we can inspect them directly when they
    # appear in the TCP payload.
    text = payload.decode("utf-8", errors="ignore")
    lines = text.replace("\r\n", "\n").split("\n")

    if not lines or not any(lines[0].startswith(method) for method in HTTP_METHODS):
        return False, None

    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            return True, host or None

    return True, None


def _read_interface_field(interface_item: Any, field_name: str) -> Any:
    """Read a field from either a Scapy interface object or a test dictionary."""

    if isinstance(interface_item, dict):
        return interface_item.get(field_name)
    return getattr(interface_item, field_name, None)


def choose_windows_wifi_interface(interfaces: list[Any], default_iface: Any = None) -> Any:
    """Pick the best Wi-Fi-looking Windows interface, or fall back to the default."""

    if not interfaces:
        return default_iface

    keywords = ("wi-fi", "wifi", "wireless", "wlan", "802.11")

    def score(interface_item: Any) -> int:
        text_parts = []
        for field_name in ("name", "description", "network_name", "guid", "netid"):
            value = _read_interface_field(interface_item, field_name)
            if value:
                text_parts.append(str(value).lower())

        combined_text = " ".join(text_parts)
        ip_value = _read_interface_field(interface_item, "ip") or _read_interface_field(interface_item, "ipv4")
        ip_text = str(ip_value).lower() if ip_value else ""

        current_score = 0
        if any(keyword in combined_text for keyword in keywords):
            current_score += 100
        if ip_text and not ip_text.startswith("127."):
            current_score += 10
        if "loopback" in combined_text:
            current_score -= 100
        return current_score

    best_interface = max(interfaces, key=score)
    return best_interface if score(best_interface) >= 100 else default_iface


def get_interface_display_name(interface_item: Any) -> str:
    """Return a friendly interface name for the status label."""

    if interface_item is None:
        return "Unknown interface"

    for field_name in ("description", "name", "network_name", "netid"):
        value = _read_interface_field(interface_item, field_name)
        if value:
            return str(value)

    return str(interface_item)


def is_running_as_admin() -> bool:
    """Check whether the current process has Administrator privileges on Windows."""

    if os.name != "nt":
        return True

    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def rows_to_trim(row_ids: list[str], max_visible_rows: int | None = None) -> list[str]:
    """Return the oldest visible rows that should be removed from the table."""

    if max_visible_rows is None:
        max_visible_rows = MAX_VISIBLE_ROWS

    if len(row_ids) <= max_visible_rows:
        return []

    excess_count = len(row_ids) - max_visible_rows
    return row_ids[:excess_count]


def extract_dns_query_name(dns_layer: Any) -> str | None:
    """Return the first domain name found in the DNS question section."""

    if dns_layer is None:
        return None

    first_question = getattr(dns_layer, "qd", None)
    if first_question is None:
        return None

    question_candidates = list(first_question) if isinstance(first_question, (list, tuple)) else [first_question]

    # If a packet carries more than one DNS question, the first one is used
    # for display to keep the table simple and consistent.
    for question in question_candidates:
        current_question = question
        visited_questions: set[int] = set()

        while current_question is not None and id(current_question) not in visited_questions:
            visited_questions.add(id(current_question))
            display_name = format_dns_query_name_for_display(getattr(current_question, "qname", None))
            if display_name:
                return display_name

            next_question = getattr(current_question, "payload", None)
            if next_question is None or not hasattr(next_question, "qname"):
                break
            current_question = next_question

    return None


def choose_protocol_and_website(dns_query_name: str | None, default_protocol: str, payload: bytes) -> tuple[str, str]:
    """Choose the row's protocol label and website value."""

    # DNS requests usually reveal the website domain even when the later web
    # traffic is HTTPS, so DNS is checked before HTTP payload parsing.
    if dns_query_name:
        return "DNS", dns_query_name

    is_http, host = inspect_http_payload(payload) if default_protocol == "TCP" else (False, None)
    if is_http:
        return "HTTP", host if host else "N/A"

    return default_protocol, "N/A"


def packet_matches_filter(summary: PacketSummary, active_filter: str) -> bool:
    """Return whether one packet summary should be shown for the chosen filter."""

    return active_filter == "ALL" or summary.protocol == active_filter


def packet_matches_search(summary: PacketSummary, search_text: str) -> bool:
    """Return whether one packet matches the case-insensitive partial search."""

    normalized_search = search_text.strip().lower()
    if not normalized_search:
        return True

    # Partial matching improves usability because packet analysis often starts
    # from remembered fragments rather than full IP addresses or domain names.
    searchable_values = (
        summary.source_ip,
        summary.destination_ip,
        summary.website,
    )
    return any(normalized_search in value.lower() for value in searchable_values)


def _format_detail_value(value: Any) -> str:
    """Convert packet field values into readable text for the details panel."""

    if value is None:
        return "N/A"

    if isinstance(value, bytes):
        decoded_value = value.decode("utf-8", errors="ignore").strip()
        return decoded_value if decoded_value else repr(value)

    return str(value)


def _append_details_section(lines: list[str], section_title: str, fields: list[tuple[str, Any]]) -> None:
    """Append one Wireshark-style section when the packet contains that layer."""

    if not fields:
        return

    lines.append(section_title)
    for field_name, field_value in fields:
        if field_value is None:
            continue
        lines.append(f"  {field_name}: {_format_detail_value(field_value)}")
    lines.append("")


def extract_http_header_fields(payload: bytes) -> list[tuple[str, str]]:
    """Return structured HTTP header fields from a TCP payload when present."""

    is_http, _host = inspect_http_payload(payload)
    if not is_http:
        return []

    text = payload.decode("utf-8", errors="ignore")
    lines = text.replace("\r\n", "\n").split("\n")
    header_fields: list[tuple[str, str]] = []

    if lines and lines[0].strip():
        header_fields.append(("Request Line", lines[0].strip()))

    for line in lines[1:]:
        stripped_line = line.strip()
        if not stripped_line:
            break
        if ":" in stripped_line:
            header_name, header_value = stripped_line.split(":", 1)
            header_fields.append((header_name.strip(), header_value.strip()))

    return header_fields


def render_packet_details(packet_number: int, packet: Any) -> str:
    """Build the structured details text shown below the packet table."""

    lines = [f"Packet {packet_number} Details", ""]

    if Ether in packet:
        ethernet_layer = packet[Ether]
        ethernet_type = getattr(ethernet_layer, "type", None)
        ethernet_type_text = f"0x{int(ethernet_type):04x}" if isinstance(ethernet_type, int) else ethernet_type
        _append_details_section(
            lines,
            "Ethernet Header",
            [
                ("Destination MAC", getattr(ethernet_layer, "dst", None)),
                ("Source MAC", getattr(ethernet_layer, "src", None)),
                ("Type", ethernet_type_text),
            ],
        )

    if IP in packet:
        ip_layer = packet[IP]
        header_length = getattr(ip_layer, "ihl", None)
        header_length_text = f"{int(header_length) * 4} bytes" if isinstance(header_length, int) else None
        _append_details_section(
            lines,
            "IP Header",
            [
                ("Version", getattr(ip_layer, "version", None)),
                ("Header Length", header_length_text),
                ("TTL", getattr(ip_layer, "ttl", None)),
                ("Protocol Number", getattr(ip_layer, "proto", None)),
                ("Source IP", getattr(ip_layer, "src", None)),
                ("Destination IP", getattr(ip_layer, "dst", None)),
            ],
        )

    if TCP in packet:
        tcp_layer = packet[TCP]
        _append_details_section(
            lines,
            "TCP Header",
            [
                ("Source Port", getattr(tcp_layer, "sport", None)),
                ("Destination Port", getattr(tcp_layer, "dport", None)),
                ("Sequence Number", getattr(tcp_layer, "seq", None)),
                ("Acknowledgment Number", getattr(tcp_layer, "ack", None)),
                ("Flags", getattr(tcp_layer, "flags", None)),
                ("Window Size", getattr(tcp_layer, "window", None)),
            ],
        )

    if UDP in packet:
        udp_layer = packet[UDP]
        _append_details_section(
            lines,
            "UDP Header",
            [
                ("Source Port", getattr(udp_layer, "sport", None)),
                ("Destination Port", getattr(udp_layer, "dport", None)),
                ("Length", getattr(udp_layer, "len", None)),
            ],
        )

    if DNS in packet:
        dns_layer = packet[DNS]
        _append_details_section(
            lines,
            "DNS Fields",
            [
                ("Transaction ID", getattr(dns_layer, "id", None)),
                ("Query/Response", "Query" if getattr(dns_layer, "qr", 0) == 0 else "Response"),
                ("Question Count", getattr(dns_layer, "qdcount", None)),
                ("Answer Count", getattr(dns_layer, "ancount", None)),
                ("Authority Count", getattr(dns_layer, "nscount", None)),
                ("Additional Count", getattr(dns_layer, "arcount", None)),
                ("Query Name", extract_dns_query_name(dns_layer)),
            ],
        )

    http_payload = bytes(packet[Raw].load) if TCP in packet and Raw in packet else b""
    http_header_fields = extract_http_header_fields(http_payload)
    _append_details_section(lines, "HTTP Headers", http_header_fields)

    if len(lines) <= 2:
        lines.append("No packet details are available for this selection.")

    return "\n".join(lines).rstrip()


def resolve_capture_interface() -> tuple[Any, str, bool]:
    """Best-effort interface selection with a Wi-Fi preference on Windows."""

    if not SCAPY_AVAILABLE:
        return None, "Scapy is not installed", True

    default_iface = getattr(conf, "iface", None)
    default_name = get_interface_display_name(default_iface)

    if os.name != "nt":
        return default_iface, default_name, True

    try:
        # Scapy exposes working interfaces, which lets us prefer a Wi-Fi-like
        # adapter without hard-coding one exact Windows adapter name.
        working_ifaces = list(get_working_ifaces()) if get_working_ifaces else []
        selected_iface = choose_windows_wifi_interface(working_ifaces, default_iface=default_iface)
        if selected_iface is None:
            return default_iface, default_name, True
        return selected_iface, get_interface_display_name(selected_iface), selected_iface == default_iface
    except Exception:
        return default_iface, default_name, True


def build_packet_summary(packet_number: int, packet: Any) -> PacketSummary | None:
    """Extract the table values from one Scapy packet."""

    if not SCAPY_AVAILABLE or IP not in packet:
        return None

    # The IP layer contains the source and destination addresses that we show
    # in the table.
    ip_layer = packet[IP]
    has_tcp = TCP in packet
    has_udp = UDP in packet
    has_icmp = ICMP in packet
    payload = b""
    dns_query_name = None

    if has_tcp and Raw in packet:
        payload = bytes(packet[Raw].load)

    if DNS in packet and getattr(packet[DNS], "qr", 0) == 0:
        dns_query_name = extract_dns_query_name(packet[DNS])

    # HTTPS usually does not expose the Host header in plain text because the
    # web request headers are encrypted inside TLS, so DNS queries are the
    # preferred clue for identifying visited websites.
    if has_tcp:
        default_protocol = "TCP"
    elif has_udp:
        default_protocol = "UDP"
    elif has_icmp:
        default_protocol = "ICMP"
    else:
        default_protocol = "IP"

    protocol, website = choose_protocol_and_website(dns_query_name, default_protocol, payload)

    return PacketSummary(
        packet_no=packet_number,
        time_text=format_packet_timestamp(packet.time),
        source_ip=ip_layer.src,
        destination_ip=ip_layer.dst,
        # Packets without DNS or HTTP information still fall back to TCP or IP.
        protocol=protocol,
        website=website,
    )


class PacketSnifferGUI:
    """Tkinter app that shows live packet rows in a simple table."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("PacketLens")
        self.root.geometry("980x760")
        self.root.minsize(860, 520)

        self.packet_count = 0
        self.sniffer = None
        self.capturing = False
        self.packet_lock = threading.Lock()
        self.packet_history: list[PacketRecord] = []
        self.row_packet_map: dict[str, Any] = {}
        self.visible_row_lookup: dict[int, str] = {}
        self.selected_row_id: str | None = None
        self.selected_details_snapshot = "Select a packet row to inspect its full details."
        self.protocol_filter_var = tk.StringVar(value="ALL")
        self.search_var = tk.StringVar(value="")

        initial_status = "Ready to capture packets."
        if not SCAPY_AVAILABLE:
            initial_status = "Scapy is not installed. Run: pip install scapy"
        elif os.name == "nt" and not is_running_as_admin():
            initial_status = "Run this script as Administrator on Windows before capturing."

        self.status_var = tk.StringVar(value=initial_status)
        self._build_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _build_widgets(self) -> None:
        """Create the clean assignment-friendly interface."""

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        main_frame = ttk.Frame(self.root, padding=12)
        main_frame.pack(fill=tk.BOTH, expand=True)

        title_label = ttk.Label(
            main_frame,
            text="PacketLens",
            font=("Segoe UI", 14, "bold"),
        )
        title_label.pack(anchor="w", pady=(0, 10))

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(0, 10))

        self.start_button = ttk.Button(button_frame, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=(0, 8))

        self.stop_button = ttk.Button(
            button_frame,
            text="Stop Capture",
            command=self.stop_capture,
            state=tk.DISABLED,
        )
        self.stop_button.pack(side=tk.LEFT)

        filter_frame = ttk.Frame(main_frame)
        filter_frame.pack(fill=tk.X, pady=(0, 10))

        filter_label = ttk.Label(filter_frame, text="Filter Protocol:")
        filter_label.pack(side=tk.LEFT, padx=(0, 8))

        self.protocol_filter_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.protocol_filter_var,
            values=FILTER_PROTOCOL_OPTIONS,
            state="readonly",
            width=12,
        )
        self.protocol_filter_combo.pack(side=tk.LEFT)
        self.protocol_filter_combo.bind("<<ComboboxSelected>>", self._on_filter_changed)

        search_label = ttk.Label(filter_frame, text="Search:")
        search_label.pack(side=tk.LEFT, padx=(16, 8))

        self.search_entry = ttk.Entry(filter_frame, textvariable=self.search_var, width=24)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.search_var.trace_add("write", self._on_search_changed)

        self.clear_filters_button = ttk.Button(
            filter_frame,
            text="Clear Filters",
            command=self._clear_filters,
        )
        self.clear_filters_button.pack(side=tk.LEFT, padx=(8, 0))

        table_frame = ttk.Frame(main_frame)
        table_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("Packet No", "Time", "Source IP", "Destination IP", "Protocol", "Website")
        self.packet_table = ttk.Treeview(table_frame, columns=columns, show="headings", height=16)

        column_widths = {
            "Packet No": 85,
            "Time": 90,
            "Source IP": 150,
            "Destination IP": 150,
            "Protocol": 90,
            "Website": 240,
        }

        for column_name in columns:
            self.packet_table.heading(column_name, text=column_name)
            self.packet_table.column(column_name, width=column_widths[column_name], anchor="center")

        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.packet_table.yview)
        self.packet_table.configure(yscrollcommand=scrollbar.set)

        self.packet_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_table.bind("<<TreeviewSelect>>", self._on_packet_selected)

        details_frame = ttk.LabelFrame(main_frame, text="Packet Details", padding=8)
        details_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        self.packet_details_text = tk.Text(
            details_frame,
            wrap="word",
            height=16,
            state=tk.DISABLED,
            font=("Consolas", 10),
        )
        details_scrollbar = ttk.Scrollbar(
            details_frame,
            orient=tk.VERTICAL,
            command=self.packet_details_text.yview,
        )
        self.packet_details_text.configure(yscrollcommand=details_scrollbar.set)

        self.packet_details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        details_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self._set_details_text(self.selected_details_snapshot)

        status_label = ttk.Label(
            main_frame,
            textvariable=self.status_var,
            anchor="w",
            relief=tk.SOLID,
            padding=(8, 6),
        )
        status_label.pack(fill=tk.X, pady=(10, 0))

    def start_capture(self) -> None:
        """Start packet capture without blocking the Tkinter event loop."""

        if self.capturing:
            return

        if not SCAPY_AVAILABLE:
            self.status_var.set("Scapy is not installed. Run: pip install scapy")
            return

        # Packet sniffing opens raw capture access, which normally requires
        # Administrator privileges on Windows.
        if os.name == "nt" and not is_running_as_admin():
            self.status_var.set("Administrator privileges are required for packet sniffing on Windows.")
            return

        capture_iface, _iface_name, _used_fallback = resolve_capture_interface()
        if capture_iface is None:
            self.status_var.set("No capture interface is available.")
            return

        self._clear_table()

        with self.packet_lock:
            # Reset for a new capture session. During the session, packet
            # numbers keep increasing even when old visible rows are trimmed.
            self.packet_count = 0
            self.capturing = True

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_var.set(format_capture_status(0))

        try:
            self.sniffer = AsyncSniffer(
                iface=capture_iface,
                store=False,
                prn=self._handle_packet,
                lfilter=self._is_ipv4_packet,
            )
            self.sniffer.start()
        except Exception as exc:
            with self.packet_lock:
                self.capturing = False
            self.sniffer = None
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.status_var.set(f"Capture could not start: {exc}")

    def stop_capture(self) -> None:
        """Stop capture and restore the idle button state."""

        with self.packet_lock:
            sniffer = self.sniffer
            captured_packets = self.packet_count
            was_capturing = self.capturing
            self.capturing = False
            self.sniffer = None

        if sniffer is not None:
            try:
                sniffer.stop(join=False)
            except TypeError:
                sniffer.stop()
            except Exception:
                pass

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        if was_capturing:
            self.status_var.set(format_capture_status(captured_packets))

    def _is_ipv4_packet(self, packet: Any) -> bool:
        """Only display IPv4 packets so source and destination IPs are always available."""

        return SCAPY_AVAILABLE and IP in packet

    def _handle_packet(self, packet: Any) -> None:
        """Parse one packet inside Scapy's background thread."""

        try:
            with self.packet_lock:
                if not self.capturing:
                    return
                next_packet_number = self.packet_count + 1

            summary = build_packet_summary(next_packet_number, packet)
            if summary is None:
                return

            with self.packet_lock:
                if not self.capturing:
                    return
                self.packet_count = next_packet_number

            self.root.after(
                0,
                lambda packet_summary=summary, captured_packet=packet: self._store_packet_record(
                    packet_summary,
                    captured_packet,
                ),
            )
        except Exception:
            self.root.after(0, lambda: self.status_var.set("A packet could not be parsed, but capture continues."))

    def _insert_visible_row(self, summary: PacketSummary, packet: Any) -> str:
        """Insert one visible table row and remember its packet object."""

        inserted_row_id = self.packet_table.insert(
            "",
            tk.END,
            values=(
                summary.packet_no,
                summary.time_text,
                summary.source_ip,
                summary.destination_ip,
                summary.protocol,
                summary.website,
            ),
        )
        self.row_packet_map[inserted_row_id] = packet
        self.visible_row_lookup[summary.packet_no] = inserted_row_id
        return inserted_row_id

    def _remove_visible_row_for_packet(self, packet_number: int) -> None:
        """Remove one visible row when its packet leaves the rolling history window."""

        row_id = self.visible_row_lookup.pop(packet_number, None)
        if row_id is None:
            return

        self.row_packet_map.pop(row_id, None)
        if row_id == self.selected_row_id:
            # Keep the selected packet snapshot visible even after the row
            # disappears from the filtered view, like tools such as Wireshark.
            self.selected_row_id = None
        self.packet_table.delete(row_id)

    def _store_packet_record(self, summary: PacketSummary, packet: Any) -> str | None:
        """Store one captured packet in the rolling history buffer and update the table."""

        # Rebuilding and filtering only from a 1000-packet rolling buffer keeps
        # the GUI responsive during long captures without storing unlimited data.
        self.packet_history.append(PacketRecord(summary=summary, packet=packet))

        while len(self.packet_history) > MAX_VISIBLE_ROWS:
            removed_record = self.packet_history.pop(0)
            self._remove_visible_row_for_packet(removed_record.summary.packet_no)

        inserted_row_id = None
        if self._matches_current_filters(summary):
            inserted_row_id = self._insert_visible_row(summary, packet)
            self.packet_table.yview_moveto(1.0)

        self.status_var.set(format_capture_status(summary.packet_no))
        return inserted_row_id

    def _matches_current_filters(self, summary: PacketSummary) -> bool:
        """Return whether a packet matches both the protocol and search filters."""

        return packet_matches_filter(summary, self.protocol_filter_var.get()) and packet_matches_search(
            summary,
            self.search_var.get(),
        )

    def _refresh_table_from_filters(self) -> None:
        """Rebuild the visible table from the rolling history buffer and filter."""

        for item_id in self.packet_table.get_children():
            self.packet_table.delete(item_id)

        self.row_packet_map.clear()
        self.visible_row_lookup.clear()
        self.selected_row_id = None

        for record in self.packet_history:
            if self._matches_current_filters(record.summary):
                self._insert_visible_row(record.summary, record.packet)

    def _on_filter_changed(self, _event: Any) -> None:
        """Refresh visible rows immediately when the protocol filter changes."""

        self._refresh_table_from_filters()

    def _on_search_changed(self, *_args: Any) -> None:
        """Refresh visible rows immediately while the user types search text."""

        self._refresh_table_from_filters()

    def _clear_filters(self) -> None:
        """Reset the filter controls and restore the current rolling history view."""

        # Quick filter reset improves usability during packet analysis
        # demonstrations, especially after several narrow searches.
        self.protocol_filter_var.set("ALL")
        if self.search_var.get():
            self.search_var.set("")
        else:
            self._refresh_table_from_filters()

    def _on_packet_selected(self, _event: Any) -> None:
        """Render full details when the user selects a different visible row."""

        selected_rows = self.packet_table.selection()
        if not selected_rows:
            return

        row_id = selected_rows[0]
        if row_id == self.selected_row_id:
            return

        packet = self.row_packet_map.get(row_id)
        if packet is None:
            return

        row_values = self.packet_table.item(row_id, "values")
        packet_number = int(row_values[0]) if row_values else 0
        details_text = render_packet_details(packet_number, packet)

        self.selected_row_id = row_id
        self.selected_details_snapshot = details_text
        self._set_details_text(details_text)

    def _set_details_text(self, details_text: str) -> None:
        """Update the read-only details panel with the latest rendered snapshot."""

        self.packet_details_text.config(state=tk.NORMAL)
        self.packet_details_text.delete("1.0", tk.END)
        self.packet_details_text.insert("1.0", details_text)
        self.packet_details_text.config(state=tk.DISABLED)

    def _clear_table(self) -> None:
        """Remove rows from the previous capture run."""

        for item_id in self.packet_table.get_children():
            self.packet_table.delete(item_id)
        self.packet_history.clear()
        self.row_packet_map.clear()
        self.visible_row_lookup.clear()
        self.selected_row_id = None

    def on_close(self) -> None:
        """Stop the sniffer before closing the window."""

        self.stop_capture()
        self.root.destroy()


class HelperFunctionTests(unittest.TestCase):
    """Small tests for pure helper functions used by the GUI."""

    class _FakeDNSQuestion:
        def __init__(self, qname: Any, payload: Any = None) -> None:
            self.qname = qname
            self.payload = payload

    class _FakeDNSLayer:
        def __init__(self, qd: Any = None) -> None:
            self.qd = qd

    class _FakeLayer:
        def __init__(self, **fields: Any) -> None:
            for field_name, field_value in fields.items():
                setattr(self, field_name, field_value)

    class _FakePacket:
        def __init__(self, layers: dict[Any, Any], time_value: float = 1700000000.0) -> None:
            self._layers = layers
            self.time = time_value

        def __contains__(self, layer_name: Any) -> bool:
            return layer_name in self._layers

        def __getitem__(self, layer_name: Any) -> Any:
            return self._layers[layer_name]

    def _patch_fake_scapy_layers(self) -> tuple[dict[str, Any], dict[str, Any]]:
        original_values = {
            "SCAPY_AVAILABLE": globals().get("SCAPY_AVAILABLE"),
            "Ether": globals().get("Ether"),
            "ICMP": globals().get("ICMP"),
            "IP": globals().get("IP"),
            "TCP": globals().get("TCP"),
            "UDP": globals().get("UDP"),
            "DNS": globals().get("DNS"),
            "Raw": globals().get("Raw"),
        }
        fake_tokens = {
            "Ether": object(),
            "ICMP": object(),
            "IP": object(),
            "TCP": object(),
            "UDP": object(),
            "DNS": object(),
            "Raw": object(),
        }

        globals()["SCAPY_AVAILABLE"] = True
        for token_name, token_value in fake_tokens.items():
            globals()[token_name] = token_value

        return original_values, fake_tokens

    def _restore_fake_scapy_layers(self, original_values: dict[str, Any]) -> None:
        for name, value in original_values.items():
            globals()[name] = value

    def test_extracts_http_host_from_request(self) -> None:
        payload = (
            b"GET / HTTP/1.1\r\n"
            b"Host: google.com\r\n"
            b"User-Agent: Test\r\n\r\n"
        )

        is_http, host = inspect_http_payload(payload)

        self.assertTrue(is_http)
        self.assertEqual(host, "google.com")

    def test_returns_none_for_non_http_payload(self) -> None:
        is_http, host = inspect_http_payload(b"\x16\x03\x01\x02\x00")

        self.assertFalse(is_http)
        self.assertIsNone(host)

    def test_formats_timestamp_as_clock_time(self) -> None:
        formatted = format_packet_timestamp(1700000000.0)
        self.assertRegex(formatted, r"^\d{2}:\d{2}:\d{2}$")

    def test_selects_wifi_interface_from_windows_names(self) -> None:
        interfaces = [
            {"name": "Ethernet", "description": "Ethernet Adapter", "ip": "10.0.0.8"},
            {"name": "Intel Wireless", "description": "Wi-Fi", "ip": "192.168.1.20"},
        ]

        selected = choose_windows_wifi_interface(interfaces, default_iface="default")

        self.assertEqual(selected, interfaces[1])

    def test_falls_back_to_default_interface(self) -> None:
        interfaces = [{"name": "Ethernet", "description": "LAN Adapter", "ip": "10.0.0.8"}]

        selected = choose_windows_wifi_interface(interfaces, default_iface="default")

        self.assertEqual(selected, "default")

    def test_formats_live_capture_status(self) -> None:
        self.assertEqual(format_capture_status(7), "Captured: 7 packets")

    def test_returns_oldest_rows_to_trim_when_limit_is_exceeded(self) -> None:
        row_ids = ["row1", "row2", "row3", "row4"]

        self.assertEqual(rows_to_trim(row_ids, max_visible_rows=3), ["row1"])

    def test_returns_no_rows_to_trim_when_under_limit(self) -> None:
        row_ids = ["row1", "row2", "row3"]

        self.assertEqual(rows_to_trim(row_ids, max_visible_rows=3), [])

    def test_formats_dns_query_name_for_display(self) -> None:
        formatted = format_dns_query_name_for_display(b"WWW.Google.COM.")

        self.assertEqual(formatted, "www.google.com")

    def test_extracts_first_dns_query_name_from_question_chain(self) -> None:
        second_question = self._FakeDNSQuestion(b"images.google.com.")
        first_question = self._FakeDNSQuestion(b"WWW.Google.COM.", payload=second_question)
        dns_layer = self._FakeDNSLayer(qd=first_question)

        self.assertEqual(extract_dns_query_name(dns_layer), "www.google.com")

    def test_dns_detection_is_preferred_over_http_host_detection(self) -> None:
        protocol, website = choose_protocol_and_website(
            dns_query_name="www.google.com",
            default_protocol="TCP",
            payload=(
                b"GET / HTTP/1.1\r\n"
                b"Host: example.com\r\n\r\n"
            ),
        )

        self.assertEqual(protocol, "DNS")
        self.assertEqual(website, "www.google.com")

    def test_udp_packets_keep_udp_protocol_label(self) -> None:
        protocol, website = choose_protocol_and_website(
            dns_query_name=None,
            default_protocol="UDP",
            payload=b"",
        )

        self.assertEqual(protocol, "UDP")
        self.assertEqual(website, "N/A")

    def test_icmp_packets_keep_icmp_protocol_label(self) -> None:
        protocol, website = choose_protocol_and_website(
            dns_query_name=None,
            default_protocol="ICMP",
            payload=b"",
        )

        self.assertEqual(protocol, "ICMP")
        self.assertEqual(website, "N/A")

    def test_packet_matches_filter_uses_summary_protocol(self) -> None:
        summary = PacketSummary(9, "12:00:09", "1.1.1.1", "8.8.8.8", "DNS", "google.com")

        self.assertTrue(packet_matches_filter(summary, "ALL"))
        self.assertTrue(packet_matches_filter(summary, "DNS"))
        self.assertFalse(packet_matches_filter(summary, "HTTP"))

    def test_packet_matches_search_uses_case_insensitive_partial_matching(self) -> None:
        summary = PacketSummary(9, "12:00:09", "192.168.1.5", "8.8.8.8", "DNS", "Google.COM")

        self.assertTrue(packet_matches_search(summary, "8.8"))
        self.assertTrue(packet_matches_search(summary, "google"))
        self.assertTrue(packet_matches_search(summary, "192.168"))
        self.assertFalse(packet_matches_search(summary, "cloudflare"))

    def test_renders_structured_packet_details_for_dns_packet(self) -> None:
        original_values, fake_tokens = self._patch_fake_scapy_layers()

        try:
            dns_layer = self._FakeLayer(
                id=100,
                qr=0,
                qdcount=1,
                ancount=0,
                nscount=0,
                arcount=0,
                qd=self._FakeDNSQuestion(b"WWW.Google.COM."),
            )
            packet = self._FakePacket(
                {
                    fake_tokens["Ether"]: self._FakeLayer(
                        src="00:11:22:33:44:55",
                        dst="aa:bb:cc:dd:ee:ff",
                        type=0x0800,
                    ),
                    fake_tokens["IP"]: self._FakeLayer(
                        version=4,
                        ihl=5,
                        ttl=64,
                        proto=17,
                        src="192.168.1.5",
                        dst="8.8.8.8",
                    ),
                    fake_tokens["UDP"]: self._FakeLayer(sport=53000, dport=53, len=40),
                    fake_tokens["DNS"]: dns_layer,
                }
            )

            details_text = render_packet_details(5, packet)

            self.assertIn("Ethernet Header", details_text)
            self.assertIn("IP Header", details_text)
            self.assertIn("UDP Header", details_text)
            self.assertIn("DNS Fields", details_text)
            self.assertIn("Query Name: www.google.com", details_text)
        finally:
            self._restore_fake_scapy_layers(original_values)

    def test_keeps_selected_details_snapshot_after_trim(self) -> None:
        original_values, fake_tokens = self._patch_fake_scapy_layers()
        original_visible_limit = globals().get("MAX_VISIBLE_ROWS")
        root = None

        try:
            globals()["MAX_VISIBLE_ROWS"] = 1
            root = tk.Tk()
            root.withdraw()
            app = PacketSnifferGUI(root)

            first_packet = self._FakePacket(
                {
                    fake_tokens["IP"]: self._FakeLayer(
                        version=4,
                        ihl=5,
                        ttl=64,
                        proto=6,
                        src="192.168.1.10",
                        dst="142.250.183.78",
                    ),
                    fake_tokens["TCP"]: self._FakeLayer(
                        sport=50000,
                        dport=80,
                        seq=1,
                        ack=1,
                        flags="PA",
                        window=1024,
                    ),
                    fake_tokens["Raw"]: self._FakeLayer(
                        load=(
                            b"GET / HTTP/1.1\r\n"
                            b"Host: google.com\r\n\r\n"
                        )
                    ),
                }
            )
            second_packet = self._FakePacket(
                {
                    fake_tokens["IP"]: self._FakeLayer(
                        version=4,
                        ihl=5,
                        ttl=60,
                        proto=17,
                        src="192.168.1.10",
                        dst="8.8.8.8",
                    ),
                    fake_tokens["UDP"]: self._FakeLayer(sport=53001, dport=53, len=40),
                    fake_tokens["DNS"]: self._FakeLayer(
                        id=101,
                        qr=0,
                        qdcount=1,
                        ancount=0,
                        nscount=0,
                        arcount=0,
                        qd=self._FakeDNSQuestion(b"openai.com."),
                    ),
                }
            )

            first_row_id = app._store_packet_record(
                PacketSummary(1, "12:00:00", "192.168.1.10", "142.250.183.78", "HTTP", "google.com"),
                first_packet,
            )
            app.packet_table.selection_set(first_row_id)
            app._on_packet_selected(None)
            first_snapshot = app.selected_details_snapshot

            app._store_packet_record(
                PacketSummary(2, "12:00:01", "192.168.1.10", "8.8.8.8", "DNS", "openai.com"),
                second_packet,
            )

            self.assertEqual(app.selected_details_snapshot, first_snapshot)
            self.assertEqual(app.packet_details_text.get("1.0", "end-1c"), first_snapshot)
            self.assertNotIn(first_row_id, app.row_packet_map)
        finally:
            if root is not None:
                root.destroy()
            globals()["MAX_VISIBLE_ROWS"] = original_visible_limit
            self._restore_fake_scapy_layers(original_values)

    def test_filter_change_rebuilds_table_from_rolling_history_buffer(self) -> None:
        root = None

        try:
            root = tk.Tk()
            root.withdraw()
            app = PacketSnifferGUI(root)

            app._store_packet_record(
                PacketSummary(1, "12:00:00", "1.1.1.1", "8.8.8.8", "DNS", "google.com"),
                object(),
            )
            app._store_packet_record(
                PacketSummary(2, "12:00:01", "1.1.1.1", "93.184.216.34", "HTTP", "example.com"),
                object(),
            )

            app.protocol_filter_var.set("DNS")
            app._on_filter_changed(None)

            visible_rows = app.packet_table.get_children()
            self.assertEqual(len(visible_rows), 1)
            self.assertEqual(app.packet_table.item(visible_rows[0], "values")[0], "1")
        finally:
            if root is not None:
                root.destroy()

    def test_filter_change_keeps_selected_snapshot_when_packet_becomes_hidden(self) -> None:
        root = None

        try:
            root = tk.Tk()
            root.withdraw()
            app = PacketSnifferGUI(root)

            http_packet = self._FakePacket({})
            dns_packet = self._FakePacket({})

            first_row_id = app._store_packet_record(
                PacketSummary(1, "12:00:00", "1.1.1.1", "93.184.216.34", "HTTP", "example.com"),
                http_packet,
            )
            app._store_packet_record(
                PacketSummary(2, "12:00:01", "1.1.1.1", "8.8.8.8", "DNS", "google.com"),
                dns_packet,
            )

            app.packet_table.selection_set(first_row_id)
            app._on_packet_selected(None)
            first_snapshot = app.selected_details_snapshot

            app.protocol_filter_var.set("DNS")
            app._on_filter_changed(None)

            self.assertEqual(app.packet_details_text.get("1.0", "end-1c"), first_snapshot)
            self.assertIsNone(app.selected_row_id)
            self.assertEqual(len(app.packet_table.get_children()), 1)
        finally:
            if root is not None:
                root.destroy()

    def test_search_change_rebuilds_table_from_rolling_history_buffer(self) -> None:
        root = None

        try:
            root = tk.Tk()
            root.withdraw()
            app = PacketSnifferGUI(root)

            app._store_packet_record(
                PacketSummary(1, "12:00:00", "192.168.1.5", "8.8.8.8", "DNS", "google.com"),
                object(),
            )
            app._store_packet_record(
                PacketSummary(2, "12:00:01", "10.0.0.5", "1.1.1.1", "HTTP", "example.com"),
                object(),
            )

            app.search_var.set("google")
            app._on_search_changed()

            visible_rows = app.packet_table.get_children()
            self.assertEqual(len(visible_rows), 1)
            self.assertEqual(app.packet_table.item(visible_rows[0], "values")[0], "1")
        finally:
            if root is not None:
                root.destroy()

    def test_search_and_protocol_filter_both_apply(self) -> None:
        root = None

        try:
            root = tk.Tk()
            root.withdraw()
            app = PacketSnifferGUI(root)

            app._store_packet_record(
                PacketSummary(1, "12:00:00", "192.168.1.5", "8.8.8.8", "DNS", "google.com"),
                object(),
            )
            app._store_packet_record(
                PacketSummary(2, "12:00:01", "192.168.1.8", "8.8.4.4", "HTTP", "google.com"),
                object(),
            )

            app.protocol_filter_var.set("DNS")
            app.search_var.set("google")
            app._refresh_table_from_filters()

            visible_rows = app.packet_table.get_children()
            self.assertEqual(len(visible_rows), 1)
            self.assertEqual(app.packet_table.item(visible_rows[0], "values")[4], "DNS")
        finally:
            if root is not None:
                root.destroy()

    def test_clear_filters_resets_controls_and_rebuilds_table(self) -> None:
        root = None

        try:
            root = tk.Tk()
            root.withdraw()
            app = PacketSnifferGUI(root)

            app._store_packet_record(
                PacketSummary(1, "12:00:00", "192.168.1.5", "8.8.8.8", "DNS", "google.com"),
                object(),
            )
            app._store_packet_record(
                PacketSummary(2, "12:00:01", "10.0.0.5", "1.1.1.1", "HTTP", "example.com"),
                object(),
            )

            app.protocol_filter_var.set("DNS")
            app.search_var.set("google")
            app._refresh_table_from_filters()
            app._clear_filters()

            self.assertEqual(app.protocol_filter_var.get(), "ALL")
            self.assertEqual(app.search_var.get(), "")
            self.assertEqual(len(app.packet_table.get_children()), 2)
        finally:
            if root is not None:
                root.destroy()


def main() -> None:
    """Launch the Tkinter application."""

    root = tk.Tk()
    PacketSnifferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
