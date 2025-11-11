import argparse
import base64
import json
import os
import random
import string
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Tuple, Optional

try:
    from azure.iot.hub import IoTHubRegistryManager
except ImportError as e:
    raise SystemExit(
        "Missing dependency 'azure-iot-hub'. Install with: pip install azure-iot-hub"
    ) from e

# Optional: load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


@dataclass
class SoftwareItem:
    name: str
    version: str


@dataclass
class DeviceRecord:
    deviceId: str
    deviceType: str
    primaryKey: str
    secondaryKey: str
    connectionString: str
    manufacturer: str
    osName: str
    osVersion: str
    software: List[SoftwareItem]


MEDICAL_TYPES = [
    "ECG",
    "InfusionPump",
    "PulseOximeter",
    "Ventilator",
    "BloodPressureMonitor",
    "Glucometer",
    "Thermometer",
    "Defibrillator",
    "EEG",
    "Ultrasound",
]


def parse_software_list(text: str) -> List[SoftwareItem]:
    items: List[SoftwareItem] = []
    if not text:
        return items
    for part in text.split(","):
        part = part.strip()
        if not part:
            continue
        if ":" in part:
            name, version = part.split(":", 1)
        elif "=" in part:
            name, version = part.split("=", 1)
        else:
            name, version = part, ""
        items.append(SoftwareItem(name=name.strip(), version=version.strip()))
    return items


def random_base64_key(num_bytes: int = 32) -> str:
    return base64.b64encode(os.urandom(num_bytes)).decode("ascii")


def sanitize_device_component(text: str) -> str:
    # Azure IoT Hub allowed characters for deviceId include alphanumerics and
    # - : . + % _ # * ? ! ( ) , = @ ; $
    allowed_extra = set("-:.+%_#*?!(),=@;$")
    out_chars: List[str] = []
    last_was_sep = False
    for ch in text:
        if ch.isalnum():
            out_chars.append(ch.lower())
            last_was_sep = False
        elif ch in allowed_extra or ch == ' ':
            # Treat spaces as separator '-'
            if not last_was_sep:
                out_chars.append('-' if ch == ' ' else ch)
            last_was_sep = (ch == ' ' or ch == '-')
        else:
            # replace invalid with single '-'
            if not last_was_sep:
                out_chars.append('-')
                last_was_sep = True
    # trim leading/trailing separators
    result = ''.join(out_chars).strip('-')
    return result or "device"


def parse_device_names(text: Optional[str]) -> Optional[List[str]]:
    if not text:
        return None
    names = [p.strip() for p in text.split(',') if p.strip()]
    return names or None


def parse_iothub_hostname(hub_conn_str: str) -> str:
    for seg in hub_conn_str.split(";"):
        if seg.startswith("HostName="):
            return seg.split("=", 1)[1]
    raise ValueError("Could not find HostName in IoT Hub connection string")


def build_device_connection_string(hostname: str, device_id: str, key: str) -> str:
    return f"HostName={hostname};DeviceId={device_id};SharedAccessKey={key}"


def ensure_device(
    registry: IoTHubRegistryManager,
    device_id: str,
    primary_key: str,
    secondary_key: str,
) -> Tuple[str, str]:
    try:
        registry.create_device_with_sas(device_id, primary_key, secondary_key, "enabled")
        return primary_key, secondary_key
    except Exception:
        # If device already exists, fetch current keys
        device = registry.get_device(device_id)
        # auth and keys properties vary by SDK versions; handle defensively
        try:
            pk = device.authentication.symmetric_key.primary_key
            sk = device.authentication.symmetric_key.secondary_key
        except Exception:
            # Fallbacks for older models
            pk = getattr(device, "primaryKey", None) or getattr(device, "primary_key", None)
            sk = getattr(device, "secondaryKey", None) or getattr(device, "secondary_key", None)
        if not pk or not sk:
            # As a last resort, rotate keys to the provided ones
            registry.update_device_with_sas(device_id, primary_key, secondary_key, "enabled", device.etag)
            pk, sk = primary_key, secondary_key
        return pk, sk


def update_twin_tags(
    registry: IoTHubRegistryManager,
    device_id: str,
    tags: Dict,
) -> None:
    twin = registry.get_twin(device_id)
    patch = {"tags": tags}
    registry.update_twin(device_id, patch, twin.etag)


def create_devices(
    hub_conn_str: str,
    count: int,
    prefix: str,
    manufacturer: str,
    os_name: str,
    os_version: str,
    software_list: List[SoftwareItem],
    device_names: Optional[List[str]] = None,
) -> List[DeviceRecord]:
    registry = IoTHubRegistryManager(hub_conn_str)
    hostname = parse_iothub_hostname(hub_conn_str)

    records: List[DeviceRecord] = []
    for i in range(count):
        label = (
            device_names[i % len(device_names)] if device_names else MEDICAL_TYPES[i % len(MEDICAL_TYPES)]
        )
        type_component = sanitize_device_component(label)
        device_type = label
        # device id: prefix-sanitizedlabel-###
        device_id = f"{prefix}-{type_component}-{i + 1:03d}"

        pk = random_base64_key()
        sk = random_base64_key()
        pk, sk = ensure_device(registry, device_id, pk, sk)

        conn_str = build_device_connection_string(hostname, device_id, pk)

        tags = {
            "deviceCategory": "Medical",
            "deviceType": device_type,
            "manufacturer": manufacturer,
            "os": {"name": os_name, "version": os_version},
            "software": [{"name": s.name, "version": s.version} for s in software_list],
        }
        update_twin_tags(registry, device_id, tags)

        records.append(
            DeviceRecord(
                deviceId=device_id,
                deviceType=device_type,
                primaryKey=pk,
                secondaryKey=sk,
                connectionString=conn_str,
                manufacturer=manufacturer,
                osName=os_name,
                osVersion=os_version,
                software=software_list,
            )
        )

    return records


def write_outputs(records: List[DeviceRecord], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # JSON
    json_path = out_dir / "devices.json"
    with json_path.open("w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in records], f, indent=2)

    # CSV
    import csv

    csv_path = out_dir / "devices.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "deviceId",
            "deviceType",
            "manufacturer",
            "osName",
            "osVersion",
            "primaryKey",
            "secondaryKey",
            "connectionString",
            "software",
        ])
        for r in records:
            software_str = ";".join([f"{s.name}:{s.version}" for s in r.software])
            writer.writerow([
                r.deviceId,
                r.deviceType,
                r.manufacturer,
                r.osName,
                r.osVersion,
                r.primaryKey,
                r.secondaryKey,
                r.connectionString,
                software_str,
            ])


def main():
    parser = argparse.ArgumentParser(
        description="Register devices in Azure IoT Hub with medical tags"
    )
    parser.add_argument(
        "--hub-conn",
        dest="hub_conn",
        help="IoT Hub connection string with registry permissions. Can also be set via env IOTHUB_CONNECTION_STRING.",
    )
    parser.add_argument(
        "--count", type=int, default=10, help="Number of devices to create (default 10)"
    )
    parser.add_argument(
        "--prefix",
        default="med",
        help="Device ID prefix (default 'med')",
    )
    parser.add_argument(
        "--manufacturer",
        default="Acme Medical Inc",
        help="Manufacturer name tag (default 'Acme Medical Inc')",
    )
    parser.add_argument(
        "--os-name",
        default="Ubuntu",
        help="OS name tag (default 'Ubuntu')",
    )
    parser.add_argument(
        "--os-version",
        default="22.04",
        help="OS version tag (default '22.04')",
    )
    parser.add_argument(
        "--software",
        default="Python:3.12,OpenSSL:3.0.13",
        help="Comma-separated software list in name:version format (default 'Python:3.12,OpenSSL:3.0.13')",
    )
    parser.add_argument(
        "--device-names",
        dest="device_names",
        help="Comma-separated device names to use (e.g., 'Health Monitor,Infusion Pump'). Overrides default medical types.",
    )
    parser.add_argument(
        "--out-dir",
        default="output",
        help="Directory to write JSON/CSV outputs (default 'output')",
    )
    args = parser.parse_args()

    hub_conn = args.hub_conn or os.getenv("IOTHUB_CONNECTION_STRING")
    if not hub_conn:
        raise SystemExit(
            "Provide IoT Hub connection string via --hub-conn or IOTHUB_CONNECTION_STRING env variable."
        )

    software_list = parse_software_list(args.software)
    device_names = parse_device_names(args.device_names)

    records = create_devices(
        hub_conn_str=hub_conn,
        count=args.count,
        prefix=args.prefix,
        manufacturer=args.manufacturer,
        os_name=args.os_name,
        os_version=args.os_version,
        software_list=software_list,
        device_names=device_names,
    )

    out_dir = Path(args.out_dir)
    write_outputs(records, out_dir)

    print(f"Created/updated {len(records)} devices. Outputs written to '{out_dir}'.")
    for r in records:
        print(f"- {r.deviceId}: {r.connectionString}")


if __name__ == "__main__":
    main()
