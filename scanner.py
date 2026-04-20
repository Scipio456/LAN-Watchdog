#!/usr/bin/env python3
"""Ethical local-network device scanner for Windows.

This tool is intentionally limited:
- It only scans the active private IPv4 subnet.
- It refuses to scan public networks.
- It never probes ports or external addresses.
- If the active subnet is larger than /24, it reduces the scan to the local /24.

Physical distance to peer devices is not exposed by standard Windows LAN APIs,
so the tool reports that as unavailable. When connected over Wi-Fi, it can
estimate the current device's distance to the access point from the Wi-Fi
signal percentage as a rough reference only.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import base64
import ctypes
import ipaddress
import json
import math
import pathlib
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Iterable


DEFAULT_VENDOR_DB_PATH = "oui_vendors.json"
DEFAULT_HISTORY_FILE = "scan_history.json"
DEFAULT_KNOWN_DEVICES_FILE = "known_devices.json"


@dataclass(frozen=True)
class PingResult:
    reachable: bool
    latency_ms: int | None


@dataclass(frozen=True)
class NetworkContext:
    interface_alias: str
    ipv4: str
    prefix_length: int
    gateway: str | None
    network: ipaddress.IPv4Network
    scan_network: ipaddress.IPv4Network


@dataclass(frozen=True)
class WifiInfo:
    connected: bool
    ssid: str | None
    bssid: str | None
    signal_percent: int | None
    radio_type: str | None


@dataclass(frozen=True)
class RouterRssiObservation:
    mac_address: str
    rssi_dbm: float
    frequency_mhz: float
    ap_name: str | None
    source_name: str | None
    client_name: str | None
    estimated_distance_m: float
    estimated_distance_cm: int
    note: str


def classify_local_proximity(latency_ms: int | None) -> str:
    if latency_ms is None:
        return "unknown"
    if latency_ms <= 10:
        return "very_low_latency"
    if latency_ms <= 40:
        return "low_latency"
    if latency_ms <= 120:
        return "medium_latency"
    return "high_latency"


def run_command(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip())
    return completed.stdout


def parse_route_print(output: str) -> tuple[str, str]:
    route_pattern = re.compile(
        r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(?P<gateway>(?:\d{1,3}\.){3}\d{1,3})\s+"
        r"(?P<interface>(?:\d{1,3}\.){3}\d{1,3})\s+(?P<metric>\d+)\s*$"
    )
    candidates: list[tuple[int, str, str]] = []
    for line in output.splitlines():
        match = route_pattern.match(line)
        if match:
            candidates.append(
                (
                    int(match.group("metric")),
                    match.group("interface"),
                    match.group("gateway"),
                )
            )
    if not candidates:
        raise RuntimeError("No active IPv4 default route was found.")
    candidates.sort(key=lambda item: item[0])
    _, interface_ip, gateway = candidates[0]
    return interface_ip, gateway


def parse_ipconfig(output: str) -> list[dict[str, str | None]]:
    adapters: list[dict[str, str | None]] = []
    current: dict[str, str | None] | None = None

    for raw_line in output.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue

        if not line.startswith(" ") and stripped.endswith(":"):
            current = {
                "name": stripped[:-1],
                "ipv4": None,
                "subnet_mask": None,
                "default_gateway": None,
            }
            adapters.append(current)
            continue

        if current is None or ":" not in line:
            continue

        key, value = line.split(":", 1)
        normalized_key = key.lower().replace(".", "").strip()
        value = value.strip() or None

        if "ipv4 address" in normalized_key or "autoconfiguration ipv4 address" in normalized_key:
            current["ipv4"] = value
        elif "subnet mask" in normalized_key:
            current["subnet_mask"] = value
        elif "default gateway" in normalized_key and value:
            current["default_gateway"] = value

    return adapters


def get_network_context() -> NetworkContext:
    interface_ip, gateway = parse_route_print(run_command(["route", "print", "-4"]))
    adapters = parse_ipconfig(run_command(["ipconfig"]))
    adapter = next((item for item in adapters if item["ipv4"] == interface_ip), None)

    if adapter is None or not adapter["subnet_mask"]:
        raise RuntimeError("No active IPv4 network interface with a subnet mask was found.")

    ipv4 = interface_ip
    prefix_length = ipaddress.IPv4Network(f"0.0.0.0/{adapter['subnet_mask']}").prefixlen
    network = ipaddress.IPv4Network(f"{ipv4}/{prefix_length}", strict=False)

    if not ipaddress.IPv4Address(ipv4).is_private:
        raise RuntimeError(
            f"Refusing to scan because the active IP {ipv4} is not on a private RFC1918 network."
        )

    scan_network = network
    if network.num_addresses > 256:
        scan_network = ipaddress.IPv4Network(f"{ipv4}/24", strict=False)

    return NetworkContext(
        interface_alias=str(adapter["name"]),
        ipv4=ipv4,
        prefix_length=prefix_length,
        gateway=adapter["default_gateway"] or gateway,
        network=network,
        scan_network=scan_network,
    )


def parse_netsh_value(line: str) -> tuple[str, str] | None:
    if ":" not in line:
        return None
    key, value = line.split(":", 1)
    return key.strip().lower(), value.strip()


def get_wifi_info() -> WifiInfo:
    try:
        output = run_command(["netsh", "wlan", "show", "interfaces"])
    except RuntimeError:
        return WifiInfo(False, None, None, None, None)

    values: dict[str, str] = {}
    for line in output.splitlines():
        parsed = parse_netsh_value(line)
        if parsed:
            key, value = parsed
            values[key] = value

    state = values.get("state", "").lower()
    if state != "connected":
        return WifiInfo(False, None, None, None, None)

    signal_percent = None
    signal_match = re.search(r"(\d+)%", values.get("signal", ""))
    if signal_match:
        signal_percent = int(signal_match.group(1))

    return WifiInfo(
        connected=True,
        ssid=values.get("ssid"),
        bssid=values.get("bssid"),
        signal_percent=signal_percent,
        radio_type=values.get("radio type"),
    )


def estimate_access_point_distance_meters(signal_percent: int | None) -> float | None:
    if signal_percent is None:
        return None

    # Rough mapping from Windows signal percentage to RSSI dBm.
    rssi_dbm = (signal_percent / 2.0) - 100.0
    tx_power_dbm = 20.0
    frequency_mhz = 2412.0
    exponent = (tx_power_dbm - rssi_dbm - 32.44 - 20 * math.log10(frequency_mhz)) / 20
    distance = 10 ** exponent
    return round(distance, 1)


def estimate_distance_from_rssi_dbm(
    rssi_dbm: float,
    frequency_mhz: float,
    tx_power_dbm: float = 20.0,
) -> float:
    exponent = (tx_power_dbm - rssi_dbm - 32.44 - 20 * math.log10(frequency_mhz)) / 20
    distance = 10 ** exponent
    return round(max(distance, 0.1), 1)


def meters_to_centimeters(distance_m: float | None) -> int | None:
    if distance_m is None:
        return None
    return int(round(distance_m * 100))


def ping_host(ip: str, timeout_ms: int) -> PingResult:
    command = [
        "ping",
        "-n",
        "1",
        "-w",
        str(timeout_ms),
        ip,
    ]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        return PingResult(reachable=False, latency_ms=None)

    latency_match = re.search(r"time[=<](\d+)ms", completed.stdout, re.IGNORECASE)
    latency_ms = int(latency_match.group(1)) if latency_match else None
    return PingResult(reachable=True, latency_ms=latency_ms)


def arp_probe_host(ip: str) -> str | None:
    send_arp = ctypes.windll.Iphlpapi.SendARP
    inet_addr = ctypes.windll.ws2_32.inet_addr

    destination_ip = inet_addr(ip.encode("ascii"))
    if destination_ip == -1:
        return None

    mac_buffer = ctypes.create_string_buffer(6)
    mac_length = ctypes.c_ulong(ctypes.sizeof(mac_buffer))
    result = send_arp(destination_ip, 0, mac_buffer, ctypes.byref(mac_length))
    if result != 0 or mac_length.value == 0:
        return None

    mac_bytes = mac_buffer.raw[: mac_length.value]
    return "-".join(f"{byte:02x}" for byte in mac_bytes)


def probe_hosts_with_arp(hosts: Iterable[str], workers: int) -> dict[str, str]:
    results: dict[str, str] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(arp_probe_host, host): host for host in hosts}
        for future in concurrent.futures.as_completed(futures):
            mac_address = future.result()
            if mac_address:
                results[futures[future]] = mac_address
    return results


def ping_active_hosts(hosts: Iterable[str], workers: int, timeout_ms: int) -> dict[str, PingResult]:
    results: dict[str, PingResult] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(ping_host, host, timeout_ms): host for host in hosts}
        for future in concurrent.futures.as_completed(futures):
            results[futures[future]] = future.result()
    return results


def parse_arp_table(scan_network: ipaddress.IPv4Network) -> dict[str, dict[str, str]]:
    output = run_command(["arp", "-a"])
    entries: dict[str, dict[str, str]] = {}
    pattern = re.compile(
        r"^\s*(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+"
        r"(?P<mac>(?:[0-9a-f]{2}-){5}[0-9a-f]{2})\s+"
        r"(?P<type>dynamic|static)\s*$",
        re.IGNORECASE,
    )
    for line in output.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        ip = match.group("ip")
        try:
            ip_addr = ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            continue
        if ip_addr not in scan_network:
            continue
        if ip_addr == scan_network.broadcast_address or ip_addr.is_multicast:
            continue
        mac_address = match.group("mac").lower()
        if mac_address == "ff-ff-ff-ff-ff-ff":
            continue
        entries[ip] = {
            "mac_address": mac_address,
            "entry_type": match.group("type").lower(),
        }
    return entries


def parse_netsh_neighbors(scan_network: ipaddress.IPv4Network) -> dict[str, dict[str, str]]:
    output = run_command(["netsh", "interface", "ipv4", "show", "neighbors"])
    entries: dict[str, dict[str, str]] = {}
    pattern = re.compile(
        r"^(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+"
        r"(?P<mac>(?:[0-9a-f]{2}-){5}[0-9a-f]{2}|Unreachable)\s+"
        r"(?P<state>Reachable|Stale|Delay|Probe|Permanent|Unreachable|Incomplete)\s*$",
        re.IGNORECASE,
    )
    for raw_line in output.splitlines():
        line = raw_line.strip()
        match = pattern.match(line)
        if not match:
            continue
        ip = match.group("ip")
        state = match.group("state").lower()
        # Only treat actively reachable neighbors as present. Stale/delay/probe
        # entries can linger after disconnects and prevent repeated join/leave detection.
        if state not in {"reachable", "permanent"}:
            continue
        try:
            ip_addr = ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            continue
        if ip_addr not in scan_network or ip_addr == scan_network.broadcast_address or ip_addr.is_multicast:
            continue
        mac_address = match.group("mac").lower()
        if mac_address in {"unreachable", "ff-ff-ff-ff-ff-ff"}:
            continue
        entries[ip] = {
            "mac_address": mac_address,
            "entry_type": state,
        }
    return entries


def reverse_dns(ip: str) -> str | None:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except OSError:
        return None


def resolve_hostname_from_ping(ip: str) -> str | None:
    completed = subprocess.run(
        ["ping", "-a", "-n", "1", "-w", "400", ip],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        return None

    match = re.search(r"^Pinging\s+(.+?)\s+\[(?:\d{1,3}\.){3}\d{1,3}\]", completed.stdout, re.MULTILINE)
    if not match:
        return None

    hostname = match.group(1).strip()
    return None if hostname == ip else hostname


def resolve_hostname_from_nbtstat(ip: str) -> str | None:
    completed = subprocess.run(
        ["nbtstat", "-A", ip],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        return None

    for line in completed.stdout.splitlines():
        match = re.match(r"^\s*([A-Z0-9._-]{1,15})\s+<00>\s+UNIQUE\s+Registered\s*$", line, re.IGNORECASE)
        if match:
            candidate = match.group(1).strip()
            if candidate.upper() != "WORKGROUP":
                return candidate
    return None


def resolve_hostname(ip: str) -> tuple[str | None, str]:
    hostname = reverse_dns(ip)
    if hostname:
        return hostname, "Resolved from reverse DNS."

    hostname = resolve_hostname_from_ping(ip)
    if hostname:
        return hostname, "Resolved from local ping name discovery."

    hostname = resolve_hostname_from_nbtstat(ip)
    if hostname:
        return hostname, "Resolved from NetBIOS."

    return None, "Device did not publish a hostname over reverse DNS, ping name lookup, or NetBIOS."


def build_display_name(
    ip: str,
    hostname: str | None,
    is_gateway: bool,
    mac_address: str,
    router_client_name: str | None,
    vendor_name: str | None,
) -> tuple[str, str]:
    if hostname:
        return hostname, "Device name resolved from the local network."
    if router_client_name:
        return router_client_name, "Device name supplied by the router/AP RSSI source."
    if is_gateway:
        return "Default Gateway", "This device is the local router/default gateway."
    if vendor_name:
        return f"Unknown {vendor_name} device", "Friendly name unavailable; vendor inferred from MAC OUI."
    return f"Unknown device ({mac_address[-5:]})", "The device did not publish a hostname."


def normalize_mac_address(mac_address: str | None) -> str | None:
    if mac_address is None:
        return None
    stripped = re.sub(r"[^0-9A-Fa-f]", "", mac_address)
    if len(stripped) != 12:
        return None
    normalized = stripped.lower()
    return "-".join(normalized[index : index + 2] for index in range(0, 12, 2))


def is_locally_administered_mac(mac_address: str) -> bool:
    first_octet = int(mac_address.split("-", 1)[0], 16)
    return bool(first_octet & 0x02)


def normalize_oui_prefix(prefix: str) -> str | None:
    stripped = re.sub(r"[^0-9A-Fa-f]", "", prefix)
    if len(stripped) < 6 or len(stripped) % 2 != 0:
        return None
    normalized = stripped.lower()
    return "-".join(normalized[index : index + 2] for index in range(0, len(normalized), 2))


def load_vendor_database(source: str | None) -> tuple[dict[str, str], str | None]:
    if not source:
        default_path = pathlib.Path(DEFAULT_VENDOR_DB_PATH)
        if not default_path.exists():
            return {}, None
        source = str(default_path)

    try:
        with pathlib.Path(source).open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        return {}, f"Vendor database could not be loaded: {error}"

    if not isinstance(payload, dict):
        return {}, "Vendor database must be a JSON object mapping OUI prefixes to vendor names."

    vendors: dict[str, str] = {}
    for raw_prefix, raw_vendor in payload.items():
        if not isinstance(raw_prefix, str) or not isinstance(raw_vendor, str):
            continue
        normalized_prefix = normalize_oui_prefix(raw_prefix)
        if normalized_prefix is None:
            continue
        vendors[normalized_prefix] = raw_vendor.strip()

    if not vendors:
        return {}, "Vendor database loaded, but no valid OUI prefixes were found."
    return vendors, None


def lookup_vendor_name(mac_address: str, vendor_database: dict[str, str]) -> str | None:
    if is_locally_administered_mac(mac_address):
        return "Private / Randomized MAC"
    best_match = None
    for prefix, vendor in vendor_database.items():
        if mac_address.startswith(prefix):
            if best_match is None or len(prefix) > len(best_match[0]):
                best_match = (prefix, vendor)
    return best_match[1] if best_match else None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_history(source: str) -> tuple[dict, str | None]:
    path = pathlib.Path(source)
    if not path.exists():
        return {"version": 1, "scans": []}, None
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        return {"version": 1, "scans": []}, f"History file could not be loaded: {error}"

    scans = payload.get("scans")
    if not isinstance(scans, list):
        return {"version": 1, "scans": []}, "History file format is invalid; starting with an empty history."
    return {"version": 1, "scans": scans}, None


def save_history(source: str, history: dict) -> None:
    path = pathlib.Path(source)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(history, handle, indent=2)


def load_known_devices(source: str | None) -> tuple[dict[str, dict[str, str]], str | None]:
    if not source:
        default_path = pathlib.Path(DEFAULT_KNOWN_DEVICES_FILE)
        if not default_path.exists():
            return {}, None
        source = str(default_path)

    try:
        with pathlib.Path(source).open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        return {}, f"Known devices file could not be loaded: {error}"

    entries = payload.get("known_devices") if isinstance(payload, dict) else None
    if not isinstance(entries, list):
        return {}, "Known devices file must contain a 'known_devices' list."

    known_devices: dict[str, dict[str, str]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        mac_address = normalize_mac_address(str(entry.get("mac_address", "")))
        if mac_address is None:
            continue
        known_devices[mac_address] = {
            "label": str(entry.get("label", "")).strip(),
            "notes": str(entry.get("notes", "")).strip(),
        }
    return known_devices, None


def classify_device_type(
    display_name: str,
    hostname: str | None,
    vendor_name: str | None,
    is_gateway: bool,
) -> tuple[str, str, str]:
    joined = f"{display_name} {hostname or ''} {vendor_name or ''}".lower()
    if is_gateway:
        return "router", "high", "Default gateway role strongly indicates a router or access point."
    if any(token in joined for token in ("printer", "epson", "hp print", "canon", "brother")):
        return "printer", "high", "Name or vendor matches common printer identifiers."
    if any(token in joined for token in ("tv", "bravia", "roku", "chromecast", "fire tv", "android tv")):
        return "tv_or_streaming", "high", "Name or vendor matches a TV or streaming device."
    if any(token in joined for token in ("camera", "cam", "cctv")):
        return "camera", "medium", "Name suggests a camera or surveillance device."
    if any(token in joined for token in ("echo", "alexa", "nest", "google home", "speaker")):
        return "smart_speaker", "medium", "Name suggests a smart speaker or assistant device."
    if any(token in joined for token in ("bulb", "plug", "switch", "iot", "tuya", "esp")):
        return "iot_device", "medium", "Name suggests a smart-home or IoT device."
    if any(token in joined for token in ("laptop", "desktop", "pc", "macbook", "thinkpad", "dell", "lenovo", "hp", "acer", "asus")):
        return "computer", "medium", "Name or vendor suggests a laptop or desktop computer."
    if any(token in joined for token in ("apple", "motorola", "samsung", "realme", "oneplus", "xiaomi", "redmi", "poco", "phone")):
        return "phone_or_tablet", "medium", "Vendor or name suggests a mobile device."
    if vendor_name == "Private / Randomized MAC":
        return "unknown", "low", "The device uses a private/randomized MAC, which weakens fingerprinting."
    if vendor_name:
        return "unknown", "low", "Only vendor information is available; there is not enough evidence for a device type."
    return "unknown", "low", "No reliable fingerprint data was available."


def build_scan_snapshot(report: dict) -> dict:
    return {
        "timestamp_utc": report["scan_timestamp_utc"],
        "current_ipv4": report["ethical_scope"]["current_ipv4"],
        "devices": [
            {
                "mac_address": device["mac_address"],
                "ip_address": device["ip_address"],
                "display_name": device["display_name"],
                "vendor_name": device["vendor_name"],
                "likely_device_type": device["likely_device_type"],
            }
            for device in report["devices"]
        ],
    }


def build_recent_history_summary(history: dict, limit: int = 3) -> list[dict]:
    scans = history.get("scans", [])
    summary = []
    for scan in scans[-limit:]:
        devices = scan.get("devices", [])
        summary.append(
            {
                "timestamp_utc": scan.get("timestamp_utc"),
                "current_ipv4": scan.get("current_ipv4"),
                "device_count": len(devices) if isinstance(devices, list) else 0,
            }
        )
    return summary


def build_history_diff(current_devices: list[dict], previous_snapshot: dict | None) -> dict:
    previous_devices = previous_snapshot.get("devices", []) if previous_snapshot else []
    previous_index = {device["mac_address"]: device for device in previous_devices if "mac_address" in device}
    current_index = {device["mac_address"]: device for device in current_devices}

    new_devices = []
    removed_devices = []
    changed_ip_devices = []

    for mac_address, device in current_index.items():
        previous = previous_index.get(mac_address)
        if previous is None:
            new_devices.append(
                {
                    "mac_address": mac_address,
                    "ip_address": device["ip_address"],
                    "display_name": device["display_name"],
                    "vendor_name": device["vendor_name"],
                }
            )
            continue
        if previous.get("ip_address") != device["ip_address"]:
            changed_ip_devices.append(
                {
                    "mac_address": mac_address,
                    "display_name": device["display_name"],
                    "previous_ip_address": previous.get("ip_address"),
                    "current_ip_address": device["ip_address"],
                }
            )

    for mac_address, previous in previous_index.items():
        if mac_address not in current_index:
            removed_devices.append(
                {
                    "mac_address": mac_address,
                    "ip_address": previous.get("ip_address"),
                    "display_name": previous.get("display_name"),
                    "vendor_name": previous.get("vendor_name"),
                }
            )

    return {
        "previous_scan_timestamp_utc": previous_snapshot.get("timestamp_utc") if previous_snapshot else None,
        "previous_device_count": len(previous_devices),
        "current_device_count": len(current_devices),
        "device_count_changed": len(previous_devices) != len(current_devices),
        "new_devices": new_devices,
        "removed_devices": removed_devices,
        "changed_ip_devices": changed_ip_devices,
    }


def build_alerts(
    current_devices: list[dict],
    history_diff: dict,
    history: dict,
    known_devices: dict[str, dict[str, str]],
) -> list[dict]:
    prior_seen_macs = {
        device.get("mac_address")
        for scan in history.get("scans", [])
        for device in scan.get("devices", [])
        if isinstance(device, dict) and device.get("mac_address")
    }

    current_index = {device["mac_address"]: device for device in current_devices}
    alerts = []
    for new_device in history_diff["new_devices"]:
        current = current_index.get(new_device["mac_address"])
        if current is None:
            continue
        if known_devices:
            if new_device["mac_address"] not in known_devices:
                alerts.append(
                    {
                        "level": "warning",
                        "type": "unknown_device_joined",
                        "message": (
                            f"Unknown device joined: {current['display_name']} at "
                            f"{current['ip_address']} ({current['mac_address']})"
                        ),
                    }
                )
        elif new_device["mac_address"] not in prior_seen_macs:
            alerts.append(
                {
                    "level": "warning",
                    "type": "first_seen_device_joined",
                    "message": (
                        f"First-seen device joined: {current['display_name']} at "
                        f"{current['ip_address']} ({current['mac_address']})"
                    ),
                }
            )
    return alerts


def is_private_router_url(source: str, gateway: str | None) -> bool:
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    host = parsed.hostname
    if host.lower() == "localhost":
        return True
    try:
        ip_host = ipaddress.ip_address(host)
    except ValueError:
        return False
    if gateway and host == gateway:
        return True
    return ip_host.is_private or ip_host.is_loopback


def load_router_rssi_payload(
    source: str,
    gateway: str | None,
    username: str | None,
    password: str | None,
    timeout_ms: int,
) -> dict:
    parsed = urllib.parse.urlparse(source)
    if parsed.scheme in {"http", "https"}:
        if not is_private_router_url(source, gateway):
            raise RuntimeError("Router RSSI URL must point to localhost or a private router/AP address.")

        request = urllib.request.Request(source)
        if username and password:
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            request.add_header("Authorization", f"Basic {token}")
        with urllib.request.urlopen(request, timeout=timeout_ms / 1000.0) as response:
            return json.load(response)

    path = pathlib.Path(source)
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def parse_router_rssi_payload(payload: dict) -> dict[str, RouterRssiObservation]:
    clients = payload.get("clients")
    if not isinstance(clients, list):
        raise RuntimeError("Router RSSI payload must contain a 'clients' list.")

    source_name = payload.get("source_name")
    observations: dict[str, RouterRssiObservation] = {}
    for client in clients:
        if not isinstance(client, dict):
            continue
        mac_address = normalize_mac_address(str(client.get("mac_address", "")))
        if mac_address is None:
            continue
        rssi_dbm = client.get("rssi_dbm")
        frequency_mhz = client.get("frequency_mhz", 2412)
        try:
            rssi_value = float(rssi_dbm)
            frequency_value = float(frequency_mhz)
        except (TypeError, ValueError):
            continue
        if frequency_value <= 0:
            continue

        estimated_distance_m = estimate_distance_from_rssi_dbm(rssi_value, frequency_value)
        observations[mac_address] = RouterRssiObservation(
            mac_address=mac_address,
            rssi_dbm=rssi_value,
            frequency_mhz=frequency_value,
            ap_name=client.get("ap_name"),
            source_name=source_name if isinstance(source_name, str) else None,
            client_name=client.get("client_name") if isinstance(client.get("client_name"), str) else None,
            estimated_distance_m=estimated_distance_m,
            estimated_distance_cm=meters_to_centimeters(estimated_distance_m) or 0,
            note=(
                "Estimated from router/AP RSSI. This is a rough radio-distance estimate and can vary with walls, "
                "interference, antenna patterns, and client orientation."
            ),
        )
    return observations


def load_router_rssi_observations(
    source: str | None,
    context: NetworkContext,
    username: str | None,
    password: str | None,
    timeout_ms: int,
) -> tuple[dict[str, RouterRssiObservation], str | None]:
    if not source:
        return {}, None
    try:
        payload = load_router_rssi_payload(source, context.gateway, username, password, timeout_ms)
        observations = parse_router_rssi_payload(payload)
        if not observations:
            return {}, "Router RSSI source loaded, but no valid client RSSI entries were found."
        return observations, None
    except (OSError, urllib.error.URLError, json.JSONDecodeError, RuntimeError) as error:
        return {}, f"Router RSSI source could not be used: {error}"


def build_peer_relationships(context: NetworkContext, devices: list[dict]) -> list[dict]:
    nodes = [
        {
            "ip_address": context.ipv4,
            "hostname": socket.gethostname(),
            "is_current_device": True,
            "latency_ms": 0,
        }
    ]
    for device in devices:
        nodes.append(
            {
                "ip_address": device["ip_address"],
                "hostname": device["hostname"],
                "is_current_device": False,
                "latency_ms": device["latency_ms"],
            }
        )

    relationships = []
    for left in nodes:
        for right in nodes:
            if left["ip_address"] >= right["ip_address"]:
                continue
            relationships.append(
                {
                    "device_a_ip": left["ip_address"],
                    "device_b_ip": right["ip_address"],
                    "device_a_hostname": left["hostname"],
                    "device_b_hostname": right["hostname"],
                    "same_local_subnet": True,
                    "network_distance_hops": 1,
                    "estimated_peer_physical_distance_m": None,
                    "proximity_band_from_current_device": (
                        classify_local_proximity(right["latency_ms"])
                        if left["is_current_device"]
                        else (
                            classify_local_proximity(left["latency_ms"])
                            if right["is_current_device"]
                            else "unknown_between_peers"
                        )
                    ),
                    "note": (
                        "Both devices are on the same private local subnet. Physical distance between peer devices "
                        "cannot be measured from this scanner. The proximity band is only available for pairs that "
                        "include the current device, and it is derived from local ping latency rather than meters."
                    ),
                }
            )
    return relationships


def resolve_hostnames(ips: Iterable[str], workers: int) -> dict[str, tuple[str | None, str]]:
    results: dict[str, tuple[str | None, str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(resolve_hostname, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            results[futures[future]] = future.result()
    return results


def build_report(
    context: NetworkContext,
    wifi_info: WifiInfo,
    router_rssi_observations: dict[str, RouterRssiObservation],
    router_rssi_warning: str | None,
    vendor_database: dict[str, str],
    vendor_warning: str | None,
    known_devices: dict[str, dict[str, str]],
    known_devices_warning: str | None,
    history: dict,
    history_warning: str | None,
) -> dict:
    hosts = [str(host) for host in context.scan_network.hosts() if str(host) != context.ipv4]
    arp_probe_results = probe_hosts_with_arp(hosts, workers=64)
    arp_entries = parse_arp_table(context.scan_network)
    neighbor_entries = parse_netsh_neighbors(context.scan_network)

    active_ips = set(arp_probe_results)
    for ip, entry in arp_entries.items():
        if context.gateway == ip:
            active_ips.add(ip)
        elif entry["mac_address"] in router_rssi_observations:
            active_ips.add(ip)
    for ip in neighbor_entries:
        active_ips.add(ip)

    sorted_active_ips = sorted(active_ips, key=ipaddress.IPv4Address)
    ping_results = ping_active_hosts(sorted_active_ips, workers=32, timeout_ms=350)
    hostname_results = resolve_hostnames(sorted_active_ips, workers=16)

    devices = []
    for ip in sorted_active_ips:
        entry = arp_entries.get(ip) or neighbor_entries.get(ip) or {
            "mac_address": arp_probe_results[ip],
            "entry_type": "dynamic",
        }
        is_gateway = context.gateway == ip
        hostname, hostname_note = hostname_results.get(ip, (None, "Hostname resolution failed."))
        ping_result = ping_results.get(ip, PingResult(reachable=False, latency_ms=None))
        router_rssi = router_rssi_observations.get(entry["mac_address"])
        vendor_name = lookup_vendor_name(entry["mac_address"], vendor_database)
        display_name, display_name_note = build_display_name(
            ip,
            hostname,
            is_gateway,
            entry["mac_address"],
            router_rssi.client_name if router_rssi else None,
            vendor_name,
        )
        known_device = known_devices.get(entry["mac_address"])
        if known_device and known_device.get("label"):
            display_name = known_device["label"]
            display_name_note = "Device label loaded from the local known devices file."
        likely_device_type, fingerprint_confidence, fingerprint_note = classify_device_type(
            display_name,
            hostname,
            vendor_name,
            is_gateway,
        )
        devices.append(
            {
                "ip_address": ip,
                "mac_address": entry["mac_address"],
                "vendor_name": vendor_name,
                "hostname": hostname,
                "hostname_note": hostname_note,
                "display_name": display_name,
                "display_name_note": display_name_note,
                "known_device": bool(known_device),
                "known_device_notes": known_device.get("notes") if known_device else None,
                "is_default_gateway": is_gateway,
                "discovery_method": "local_arp_after_icmp_within_local_subnet",
                "responded_to_probe": ping_result.reachable,
                "latency_ms": ping_result.latency_ms,
                "proximity_band_from_current_device": classify_local_proximity(ping_result.latency_ms),
                "likely_device_type": likely_device_type,
                "fingerprint_confidence": fingerprint_confidence,
                "fingerprint_note": fingerprint_note,
                "distance_from_current_device_m": None,
                "distance_note": (
                    "Physical distance for peer LAN devices cannot be measured reliably from local LAN replies."
                ),
                "router_ap_name": router_rssi.ap_name if router_rssi else None,
                "router_ap_source": router_rssi.source_name if router_rssi else None,
                "router_ap_rssi_dbm": router_rssi.rssi_dbm if router_rssi else None,
                "router_ap_frequency_mhz": router_rssi.frequency_mhz if router_rssi else None,
                "router_ap_estimated_distance_m": router_rssi.estimated_distance_m if router_rssi else None,
                "router_ap_estimated_distance_cm": router_rssi.estimated_distance_cm if router_rssi else None,
                "router_ap_note": (
                    router_rssi.note
                    if router_rssi
                    else "Router/AP RSSI data was not available for this device."
                ),
            }
        )

    ap_distance = estimate_access_point_distance_meters(wifi_info.signal_percent)
    peer_relationships = build_peer_relationships(context, devices)
    previous_snapshot = history["scans"][-1] if history.get("scans") else None
    history_diff = build_history_diff(devices, previous_snapshot)
    alerts = build_alerts(devices, history_diff, history, known_devices)

    ap_distance_cm = meters_to_centimeters(ap_distance)

    return {
        "scan_timestamp_utc": utc_now_iso(),
        "ethical_scope": {
            "mode": "local_private_subnet_only",
            "active_interface": context.interface_alias,
            "current_ipv4": context.ipv4,
            "default_gateway": context.gateway,
            "detected_network": str(context.network),
            "scan_network": str(context.scan_network),
            "scan_restricted_to_local_24": context.network != context.scan_network,
            "no_port_scan": True,
            "no_external_scan": True,
            "no_packet_capture": True,
        },
        "wifi_reference": {
            "connected": wifi_info.connected,
            "ssid": wifi_info.ssid,
            "bssid": wifi_info.bssid,
            "signal_percent": wifi_info.signal_percent,
            "radio_type": wifi_info.radio_type,
            "distance_to_access_point_m": ap_distance,
            "distance_to_access_point_cm": ap_distance_cm,
            "distance_note": (
                "This is a rough estimate for the Wi-Fi access point only, not for peer devices."
                if ap_distance is not None
                else "Wi-Fi access point distance is unavailable."
            ),
        },
        "router_rssi_reference": {
            "enabled": bool(router_rssi_observations),
            "matched_devices": sum(
                1 for device in devices if device["router_ap_estimated_distance_m"] is not None
            ),
            "warning": router_rssi_warning,
            "source_note": (
                "Router/AP RSSI estimates are optional and depend on the router exposing per-client signal data."
            ),
        },
        "vendor_reference": {
            "enabled": bool(vendor_database),
            "matched_devices": sum(1 for device in devices if device["vendor_name"]),
            "warning": vendor_warning,
            "source_note": "Vendor names are inferred locally from MAC OUI prefixes and may be affected by randomized MAC addresses.",
        },
        "known_devices_reference": {
            "enabled": bool(known_devices),
            "matched_devices": sum(1 for device in devices if device["known_device"]),
            "warning": known_devices_warning,
            "source_note": "Known device labels are loaded only from a local file and never sent outside this machine.",
        },
        "history_reference": {
            "enabled": True,
            "path": None,
            "scan_count_before_current": len(history.get("scans", [])),
            "total_scans_after_current": len(history.get("scans", [])),
            "saved": False,
            "recent_scans": build_recent_history_summary(history),
            "warning": history_warning,
            "source_note": "Scan history is stored locally to support diffs, monitoring, and alerts.",
        },
        "device_count_excluding_current_device": len(devices),
        "devices": devices,
        "peer_relationships": peer_relationships,
        "history_diff": history_diff,
        "alerts": alerts,
    }


def print_human_report(report: dict) -> None:
    scope = report["ethical_scope"]
    wifi = report["wifi_reference"]
    router_rssi_reference = report["router_rssi_reference"]
    vendor_reference = report["vendor_reference"]
    known_devices_reference = report["known_devices_reference"]
    history_reference = report["history_reference"]

    print(f"Scan time           : {report['scan_timestamp_utc']}")

    print("Ethical Local Network Scan")
    print(f"Interface           : {scope['active_interface']}")
    print(f"Current IPv4        : {scope['current_ipv4']}")
    print(f"Detected network    : {scope['detected_network']}")
    print(f"Scan network        : {scope['scan_network']}")
    print(f"Default gateway     : {scope['default_gateway'] or 'Unavailable'}")
    print(f"Devices found       : {report['device_count_excluding_current_device']}")
    print(f"Port scan           : disabled")
    print(f"External scan       : disabled")
    if scope["scan_restricted_to_local_24"]:
        print("Large subnet safety : reduced automatically to the local /24 segment")

    print()
    print("Wi-Fi Reference")
    print(f"Connected           : {'Yes' if wifi['connected'] else 'No'}")
    if wifi["ssid"]:
        print(f"SSID                : {wifi['ssid']}")
    if wifi["signal_percent"] is not None:
        print(f"Signal              : {wifi['signal_percent']}%")
    ap_distance = wifi["distance_to_access_point_m"]
    ap_distance_cm = wifi["distance_to_access_point_cm"]
    if ap_distance is None or ap_distance_cm is None:
        print("AP distance         : Unavailable")
    else:
        print(f"AP distance         : {ap_distance} m ({ap_distance_cm} cm)")
    print(f"Note                : {wifi['distance_note']}")

    print()
    print("Router/AP RSSI")
    print(f"Enabled             : {'Yes' if router_rssi_reference['enabled'] else 'No'}")
    print(f"Matched devices     : {router_rssi_reference['matched_devices']}")
    if router_rssi_reference["warning"]:
        print(f"Warning             : {router_rssi_reference['warning']}")
    print(f"Note                : {router_rssi_reference['source_note']}")

    print()
    print("MAC Vendor")
    print(f"Enabled             : {'Yes' if vendor_reference['enabled'] else 'No'}")
    print(f"Matched devices     : {vendor_reference['matched_devices']}")
    if vendor_reference["warning"]:
        print(f"Warning             : {vendor_reference['warning']}")
    print(f"Note                : {vendor_reference['source_note']}")

    print()
    print("Known Devices")
    print(f"Enabled             : {'Yes' if known_devices_reference['enabled'] else 'No'}")
    print(f"Matched devices     : {known_devices_reference['matched_devices']}")
    if known_devices_reference["warning"]:
        print(f"Warning             : {known_devices_reference['warning']}")
    print(f"Note                : {known_devices_reference['source_note']}")

    print()
    print("History")
    print(f"History file        : {history_reference['path']}")
    print(f"Previous scans      : {history_reference['scan_count_before_current']}")
    print(f"Total scans         : {history_reference['total_scans_after_current']}")
    print(f"Saved               : {'Yes' if history_reference['saved'] else 'No'}")
    if history_reference["warning"]:
        print(f"Warning             : {history_reference['warning']}")
    print(f"Note                : {history_reference['source_note']}")
    for recent in history_reference["recent_scans"]:
        print(
            f"   Snapshot         : {recent['timestamp_utc']} "
            f"devices={recent['device_count']} ip={recent['current_ipv4']}"
        )

    print()
    print("Diff")
    print(f"New devices         : {len(report['history_diff']['new_devices'])}")
    print(f"Removed devices     : {len(report['history_diff']['removed_devices'])}")
    print(f"IP changes          : {len(report['history_diff']['changed_ip_devices'])}")
    if report["history_diff"]["previous_scan_timestamp_utc"]:
        print(f"Compared to         : {report['history_diff']['previous_scan_timestamp_utc']}")
    for device in report["history_diff"]["new_devices"]:
        print(f"   New              : {device['display_name']} {device['ip_address']} {device['mac_address']}")
    for device in report["history_diff"]["removed_devices"]:
        print(f"   Removed          : {device['display_name']} {device['ip_address']} {device['mac_address']}")
    for device in report["history_diff"]["changed_ip_devices"]:
        print(
            f"   IP changed       : {device['display_name']} "
            f"{device['previous_ip_address']} -> {device['current_ip_address']}"
        )

    print()
    print("Discovered Devices")
    if not report["devices"]:
        print("No peer devices were discovered on the local scan network.")
        return

    for index, device in enumerate(report["devices"], start=1):
        gateway_marker = " (gateway)" if device["is_default_gateway"] else ""
        print(f"{index}. {device['ip_address']}{gateway_marker}")
        print(f"   Name     : {device['display_name']}")
        print(f"   Name note: {device['display_name_note']}")
        print(f"   MAC      : {device['mac_address']}")
        print(f"   Vendor   : {device['vendor_name'] or 'Unavailable'}")
        print(f"   Hostname : {device['hostname'] or 'Unavailable'}")
        latency = f"{device['latency_ms']} ms" if device["latency_ms"] is not None else "Unavailable"
        print(f"   Latency  : {latency}")
        print(f"   Proximity: {device['proximity_band_from_current_device']}")
        print(
            f"   Type     : {device['likely_device_type']} "
            f"({device['fingerprint_confidence']} confidence)"
        )
        print(f"   Type note: {device['fingerprint_note']}")
        rssi = device["router_ap_rssi_dbm"]
        router_distance_m = device["router_ap_estimated_distance_m"]
        router_distance_cm = device["router_ap_estimated_distance_cm"]
        if rssi is not None and router_distance_m is not None and router_distance_cm is not None:
            ap_label = device["router_ap_name"] or device["router_ap_source"] or "Router/AP"
            print(f"   Distance : ~{router_distance_m} m ({router_distance_cm} cm) to {ap_label}")
            print(f"   AP RSSI  : {rssi} dBm from {ap_label}")
            print(f"   AP note  : {device['router_ap_note']}")
        else:
            print("   Distance : Unavailable in meters/cm")
            print(f"   AP RSSI  : {device['router_ap_note']}")

    print()
    print("Alerts")
    if not report["alerts"]:
        print("No local alerts were triggered.")
    for alert in report["alerts"]:
        print(f"{alert['level'].upper()}: {alert['message']}")

    print()
    print("Peer Relationships")
    for relation in report["peer_relationships"]:
        print(f"{relation['device_a_ip']} <-> {relation['device_b_ip']}")
        print(f"   Network hops : {relation['network_distance_hops']}")
        print(f"   Same subnet  : {'Yes' if relation['same_local_subnet'] else 'No'}")
        print(f"   Proximity    : {relation['proximity_band_from_current_device']}")
        print("   Distance     : Not supported for peer-to-peer pairs")


def print_monitor_summary(report: dict) -> None:
    diff = report["history_diff"]
    print(f"[{report['scan_timestamp_utc']}] devices={report['device_count_excluding_current_device']}")
    if diff["device_count_changed"]:
        print(
            f"COUNT {diff['previous_device_count']} -> {diff['current_device_count']}"
        )
    if diff["new_devices"]:
        for device in diff["new_devices"]:
            print(f"JOIN  {device['display_name']} {device['ip_address']} {device['mac_address']}")
    if diff["removed_devices"]:
        for device in diff["removed_devices"]:
            print(f"LEFT  {device['display_name']} {device['ip_address']} {device['mac_address']}")
    if diff["changed_ip_devices"]:
        for device in diff["changed_ip_devices"]:
            print(
                f"IPCHG {device['display_name']} {device['previous_ip_address']} -> {device['current_ip_address']}"
            )
    if report["alerts"]:
        for alert in report["alerts"]:
            print(f"ALERT {alert['message']}")


def monitor_has_changes(report: dict) -> bool:
    diff = report["history_diff"]
    if not diff["previous_scan_timestamp_utc"]:
        return False
    return any(
        (
            diff["device_count_changed"],
            bool(diff["new_devices"]),
            bool(diff["removed_devices"]),
            bool(diff["changed_ip_devices"]),
            bool(report["alerts"]),
        )
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan only the active private local subnet and report discovered devices safely."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the report as JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--router-rssi-source",
        help=(
            "Optional local JSON file path or private router/AP URL that returns per-client RSSI data in the "
            "documented generic JSON format."
        ),
    )
    parser.add_argument(
        "--router-rssi-user",
        help="Optional username for router/AP RSSI HTTP basic auth.",
    )
    parser.add_argument(
        "--router-rssi-password",
        help="Optional password for router/AP RSSI HTTP basic auth.",
    )
    parser.add_argument(
        "--router-rssi-timeout-ms",
        type=int,
        default=3000,
        help="Timeout for router/AP RSSI HTTP requests in milliseconds.",
    )
    parser.add_argument(
        "--vendor-db",
        help=(
            "Optional local JSON file mapping MAC OUI prefixes to vendor names. "
            f"If omitted, the scanner will use {DEFAULT_VENDOR_DB_PATH} when present."
        ),
    )
    parser.add_argument(
        "--known-devices-file",
        help=(
            "Optional local JSON file containing known device MAC addresses and labels. "
            f"If omitted, the scanner will use {DEFAULT_KNOWN_DEVICES_FILE} when present."
        ),
    )
    parser.add_argument(
        "--history-file",
        default=DEFAULT_HISTORY_FILE,
        help="Local JSON file used to persist scan history and diffs.",
    )
    parser.add_argument(
        "--max-history",
        type=int,
        default=50,
        help="Maximum number of scans to retain in the local history file.",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Repeat the scan locally every few seconds and show join/leave/IP-change events in real time.",
    )
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=5,
        help="Seconds between scans in monitor mode.",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        help="Optional number of scan iterations in monitor mode. Omit to run until interrupted.",
    )
    return parser.parse_args()


def run_single_scan(args: argparse.Namespace) -> dict:
    history, history_warning = load_history(args.history_file)
    try:
        context = get_network_context()
        wifi_info = get_wifi_info()
        router_rssi_observations, router_rssi_warning = load_router_rssi_observations(
            args.router_rssi_source,
            context,
            args.router_rssi_user,
            args.router_rssi_password,
            args.router_rssi_timeout_ms,
        )
        vendor_database, vendor_warning = load_vendor_database(args.vendor_db)
        known_devices, known_devices_warning = load_known_devices(args.known_devices_file)
        report = build_report(
            context,
            wifi_info,
            router_rssi_observations,
            router_rssi_warning,
            vendor_database,
            vendor_warning,
            known_devices,
            known_devices_warning,
            history,
            history_warning,
        )
    except RuntimeError as error:
        raise RuntimeError(str(error)) from error

    snapshot = build_scan_snapshot(report)
    history["scans"].append(snapshot)
    if args.max_history > 0:
        history["scans"] = history["scans"][-args.max_history :]
    try:
        save_history(args.history_file, history)
    except OSError as error:
        raise RuntimeError(f"History file could not be saved: {error}") from error
    report["history_reference"]["path"] = args.history_file
    report["history_reference"]["saved"] = True
    report["history_reference"]["total_scans_after_current"] = len(history["scans"])
    report["history_reference"]["recent_scans"] = build_recent_history_summary(history)
    return report


def main() -> int:
    args = parse_args()
    if args.interval_seconds <= 0:
        print("Error: --interval-seconds must be greater than 0.", file=sys.stderr)
        return 1
    if args.max_history <= 0:
        print("Error: --max-history must be greater than 0.", file=sys.stderr)
        return 1

    try:
        if args.monitor:
            print(f"Monitoring every {args.interval_seconds} seconds. Waiting for network changes...", flush=True)
            iteration = 0
            while True:
                report = run_single_scan(args)
                has_changes = monitor_has_changes(report)
                
                if iteration == 0 or has_changes:
                    if iteration > 0 and not args.json:
                        print() # Clear line from heartbeat dots
                    if args.json:
                        print(json.dumps(report, indent=2), flush=True)
                    else:
                        print_monitor_summary(report)
                        sys.stdout.flush()
                elif not args.json:
                    # Heartbeat dot to show progress
                    print(".", end="", flush=True)

                iteration += 1
                if args.iterations is not None and iteration >= args.iterations:
                    break
                time.sleep(args.interval_seconds)
            if not args.json:
                print()
        else:
            report = run_single_scan(args)
            if args.json:
                print(json.dumps(report, indent=2), flush=True)
            else:
                print_human_report(report)
                sys.stdout.flush()
    except KeyboardInterrupt:
        print("Monitor stopped.", file=sys.stderr)
        return 130
    except RuntimeError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
