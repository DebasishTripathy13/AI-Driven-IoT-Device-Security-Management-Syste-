# Azure IoT Hub: Register 10 Medical Devices

This script creates (or updates) 10 IoT devices in your Azure IoT Hub and sets device twin tags for manufacturer, OS (name/version), and installed software (e.g., Python 3.12).

## Prerequisites
- Python 3.8+
- IoT Hub connection string with registry permissions (typically a policy like `iothubowner`).
- Windows PowerShell (pwsh) commands are shown below.

## Install
```pwsh
cd "c:\Users\debas\Downloads\DebasishGEfinal"
python -m venv .venv
. .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Configure secrets
Create a local `.env` by copying the example and fill in your hub connection string.

```pwsh
Copy-Item .env.example .env
# Edit .env and set IOTHUB_CONNECTION_STRING
```

## Run
Provide the IoT Hub connection string via `.env`, environment variable, or `--hub-conn` argument.

```pwsh
# Option A: via env var
$env:IOTHUB_CONNECTION_STRING = "HostName=...;SharedAccessKeyName=iothubowner;SharedAccessKey=..."
python .\register_iothub_devices.py

# Option B: via argument
python .\register_iothub_devices.py --hub-conn "HostName=...;SharedAccessKeyName=iothubowner;SharedAccessKey=..."
```

By default, it creates 10 devices named like `med-ecg-001`, `med-infusionpump-002`, ... and writes outputs to `output/devices.json` and `output/devices.csv`.

## Customization
```pwsh
python .\register_iothub_devices.py \
  --count 10 \
  --prefix med \
  --manufacturer "GE Healthcare" \
  --os-name "Ubuntu" \
  --os-version "22.04" \
  --software "Python:3.12,OpenSSL:3.0.13" \
  --device-names "Health Monitor,Infusion Pump,Pulse Oximeter"
```

- `--software` supports `name:version` pairs separated by commas. You can also use `name=version`. Example: `Python:3.12,NumPy:2.0.1`.
- `--device-names` lets you supply custom display names (e.g., `Health Monitor`). IDs are sanitized automatically, e.g., `Health Monitor` becomes `med-health-monitor-001`.

## Send Telemetry Data

Use `telemetry_client.py` to send mock medical data from the registered devices:

```pwsh
# Install the device SDK
pip install -r requirements.txt

# Send 5 messages from each device (batch mode)
python .\telemetry_client.py

# Send continuous telemetry every 10 seconds
python .\telemetry_client.py --continuous --interval 10

# Send from specific devices only
python .\telemetry_client.py --device-ids "med-ecg-001,med-pulseoximeter-003"

# Run for 60 seconds then stop
python .\telemetry_client.py --continuous --duration 60
```

The telemetry client generates realistic medical data:
- **ECG**: Heart rate, ECG waveform, rhythm analysis
- **Pulse Oximeter**: Oxygen saturation, pulse rate, perfusion index
- **Blood Pressure**: Systolic/diastolic pressure, mean arterial pressure
- **Infusion Pump**: Flow rate, pressure, volume infused
- **Ventilator**: Tidal volume, respiratory rate, PEEP, FiO2
- **Glucometer**: Glucose levels in mg/dL
- **Thermometer**: Temperature in Celsius and Fahrenheit
- **Defibrillator**: Battery status, shock energy, impedance
- **EEG**: Brain wave patterns (alpha/beta), amplitude
- **Ultrasound**: Frequency, depth, imaging mode

## Web Application

Launch the web application for a modern UI to manage devices and telemetry:

```pwsh
# Install web dependencies
pip install -r requirements.txt

# Start the web server
python main.py
```

Then open your browser to: http://localhost:8000

**Web Features:**
- **Interactive Dashboard**: Visual device status and real-time statistics
- **Device Management**: Connect/disconnect devices, view device details
- **Telemetry Control**: Send batch or continuous telemetry with custom intervals
- **Real-time Monitoring**: Live activity log and toast notifications
- **REST API**: Full REST API with Swagger documentation at `/docs`
- **Request Logging**: All API requests logged with user IP and timestamps

**API Endpoints:**
- `GET /api/devices` - List all devices
- `GET /api/devices/{device_id}` - Get device details
- `POST /api/devices/connect` - Connect devices
- `POST /api/devices/disconnect` - Disconnect devices
- `POST /api/telemetry/send` - Send telemetry batch
- `POST /api/telemetry/continuous` - Start continuous telemetry
- `GET /api/telemetry/sample/{device_type}` - Get sample data
- `PATCH /api/devices/{device_id}` - Update device properties
- `GET /api/status` - System status and statistics

All requests are logged with user IP, endpoint, method, and details in `api.log`.

## Output
- `output/devices.json`: Full details including per-device connection strings and keys.
- `output/devices.csv`: CSV with commonly needed fields including a `software` column, semicolon-delimited pairs like `Python:3.12;OpenSSL:3.0.13`.

## Notes
- The script is idempotent: if a device already exists, it reuses current keys and only updates twin tags.
- Requires policy with `RegistryRead` and `RegistryWrite` permissions.
- Device SAS connection string is built from the primary key for convenience.
- Do not commit real secrets. `.env` is ignored by `.gitignore`. Rotate keys if they were exposed.
