# Ethical Wi-Fi Device Scanner (Python + Node.js)

This project provides a Windows local network device scanner with both Python and Node.js interfaces.

- Counts devices discovered on the current device's active private local network.
- Restricts scanning to the active local subnet only.
- Avoids port scanning, packet capture, and any external network access.
- Protects personal data using environment variables and ignored local history.

## Ethical Safety Rules

The scanner is intentionally limited so it does not go outside the current device's local connection scope:

- It only uses the active IPv4 interface that has the default gateway.
- It refuses to run on a public IPv4 address.
- It scans only the detected private subnet.
- If the subnet is larger than 256 addresses, it automatically narrows the scan to the current `/24` segment.
- It only sends one ICMP ping per host to warm up the local ARP table.
- It does not scan ports, capture packets, or contact internet services.

## Installation

### Prerequisites
1. **Python 3.11 or newer** for Windows.
2. **Node.js 18 or newer** (optional, for Node CLI).

### Setup
1. Clone the repository.
2. (Optional) Install Node.js dependencies:
   ```powershell
   npm install
   ```
3. Copy `.env.example` to `.env` and configure your settings:
   ```powershell
   copy .env.example .env
   ```

## GitHub Safety & Privacy
To protect your personal information and device details:
- **`.env`**: Store sensitive information like router passwords here. It is ignored by Git.
- **`scan_history.json`**: This file contains your local network history and is ignored by Git.
- **`known_devices.json`**: This file contains your custom device labels and is ignored by Git.
- **`oui_vendors.json`**: Your local MAC vendor database is ignored by Git.

Always use the `*_sample.json` files for sharing or documentation.

## How To Run

### Using Node.js CLI (Recommended)
The Node CLI automatically loads configurations from your `.env` file.

```powershell
# Run a single scan
npm run scan

# Run in monitor mode
npm run monitor

# Run with custom arguments
node index.js --json
```

### Using Python Directly
```powershell
python scanner.py
```

For JSON output:
```powershell
python scanner.py --json
```

To add router/AP RSSI data from a private router URL:
```powershell
python scanner.py --router-rssi-source http://192.168.1.1/clients/rssi.json --router-rssi-user admin --router-rssi-password yourpassword
```

## What The Distance Output Means

- `distance_from_current_device_m` for discovered peer devices is always `null` / unavailable.
- This is by design. On a normal Wi-Fi or LAN connection, Windows does not provide a trustworthy physical-distance reading for every other device on the network.
- `distance_to_access_point_m` is a rough estimate to the Wi-Fi router or access point, based only on the current device's Wi-Fi signal percentage.
- `distance_to_access_point_cm` is the same rough Wi-Fi access-point estimate converted to centimeters.
- `router_ap_rssi_dbm` is optional per-client RSSI supplied by your router/AP, not discovered from LAN traffic alone.
- `router_ap_estimated_distance_m` and `router_ap_estimated_distance_cm` are rough radio-distance estimates from the router/AP to that client when router RSSI data is available.
- `vendor_name` is an offline vendor/brand inference from the MAC OUI prefix when a local vendor database is supplied.
- Locally administered MAC addresses are labeled as `Private / Randomized MAC`, because they usually do not reveal a reliable brand.
- `likely_device_type` is a local heuristic such as `router`, `phone_or_tablet`, `computer`, `tv_or_streaming`, or `iot_device`.
- `history_diff` shows newly seen devices, removed devices, and IP changes compared with the previous local scan.
- `alerts` are generated locally when an unknown or first-seen device joins the network.
- On some Windows systems, reading Wi-Fi signal details through `netsh` may require running the terminal as Administrator.
- `hostname` may still be unavailable if the other device does not publish its name on the local network through reverse DNS, ping name lookup, or NetBIOS.
- `latency_ms` is included as a local network response time, but it is not physical distance.
- `proximity_band_from_current_device` is a safe heuristic derived from local ping latency. It is only a relative network-proximity signal.
- `peer_relationships` shows local-subnet relationships and one-hop local network distance, not physical meter distance between peer devices.
- Peer-device distances remain unavailable in both meters and centimeters because the scanner cannot measure them reliably.

## Router RSSI JSON Format

Use a local file or private router URL that returns JSON in this shape:

```json
{
  "source_name": "Example Router Export",
  "clients": [
    {
      "mac_address": "74-fe-ce-93-c3-70",
      "client_name": "Phone",
      "rssi_dbm": -48,
      "frequency_mhz": 2412,
      "ap_name": "Living Room AP"
    }
  ]
}
```

Field meanings:

- `mac_address`: client MAC address that should match the ARP-discovered device
- `rssi_dbm`: signal level seen by the router/AP for that client
- `frequency_mhz`: Wi-Fi frequency, for example `2412` or `5180`
- `ap_name`: optional access-point label
- `client_name`: optional friendly device name supplied by the router/AP
- `source_name`: optional label for the router export source

The scanner merges this data by MAC address and calculates a rough router-to-device range.

## MAC Vendor JSON Format

Use a local file that maps OUI prefixes to vendor names:

```json
{
  "74-fe-ce": "Example Router Vendor",
  "00-1a-2b": "Example Laptop Vendor"
}
```

Notes:

- Prefixes can be three bytes or longer.
- The scanner performs a longest-prefix match against each discovered MAC address.
- Vendor inference gives you a manufacturer/brand, not the personal device name.
- Randomized/private MAC addresses may reduce accuracy.

## Known Devices JSON Format

Use a local file that defines devices you trust and want labeled consistently:

```json
{
  "known_devices": [
    {
      "mac_address": "74-fe-ce-93-c3-70",
      "label": "Home Router",
      "notes": "Main gateway"
    }
  ]
}
```

If a known devices file is present:

- matching devices are labeled from that file
- alerts treat non-listed devices as unknown
- all labels stay local to this machine

If no known devices file is present:

- alerts fall back to first-seen detection using local scan history

## History And Monitoring

The scanner stores local history in `scan_history.json` by default.

Features built on that history:

- `scan history and diff`: new devices, removed devices, changed IPs
- `live monitor mode`: repeated scans that print terminal updates when a join, leave, device-count change, or IP change is detected
- monitor mode is quiet by default and only prints when the device count, device membership, or IP assignments change
- `alerts`: local warnings when an unknown or first-seen device appears

Useful commands:

```powershell
python scanner.py
python scanner.py --monitor
python scanner.py --history-file my_history.json
python scanner.py --monitor --iterations 5
```

## Example Output

```text
Ethical Local Network Scan
Interface           : Wi-Fi
Current IPv4        : 192.168.1.10
Detected network    : 192.168.1.0/24
Scan network        : 192.168.1.0/24
Default gateway     : 192.168.1.1
Devices found       : 3
Port scan           : disabled
External scan       : disabled

Wi-Fi Reference
Connected           : Yes
SSID                : HomeWiFi
Signal              : 82%
AP distance         : 5.4
Note                : This is a rough estimate for the Wi-Fi access point only, not for peer devices.

Discovered Devices
1. 192.168.1.1 (gateway)
   MAC      : aa-bb-cc-dd-ee-ff
   Hostname : router.local
   Distance : Unavailable
```

## Limitations

- Works on Windows because it uses `PowerShell`, `netsh`, `ping`, and `arp`.
- Some devices may not answer the ICMP ping and therefore may not appear in the ARP cache.
- Reverse DNS hostnames are best-effort only.
- Physical peer-to-peer distance across devices cannot be derived accurately from a single scanner on a normal personal network.
- Router RSSI distance estimates are approximate and depend on your router exposing usable per-client signal data.
- MAC vendor inference depends on the quality of your local OUI database and may be inaccurate for randomized MAC addresses.
- Alerts, history, and labels are stored locally only; the program does not send them anywhere.
