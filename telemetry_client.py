import argparse
import asyncio
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional
import math

try:
    from azure.iot.device.aio import IoTHubDeviceClient
    from azure.iot.device import Message
except ImportError as e:
    raise SystemExit(
        "Missing dependency 'azure-iot-device'. Install with: pip install azure-iot-device"
    ) from e

# Optional: load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass


class MedicalDataGenerator:
    """Generates realistic mock telemetry data for medical devices"""
    
    def __init__(self):
        self.time_offset = 0
        
    def get_timestamp(self) -> str:
        return datetime.now(timezone.utc).isoformat()
    
    def ecg_data(self) -> Dict[str, Any]:
        """Generate ECG heart rhythm data"""
        # Simulate normal sinus rhythm around 72 BPM
        t = time.time() + self.time_offset
        heart_rate = 70 + random.gauss(0, 5)  # 70±5 BPM
        # Simplified ECG waveform simulation
        ecg_value = math.sin(t * heart_rate / 60 * 2 * math.pi) * 1.2
        ecg_value += random.gauss(0, 0.1)  # Add noise
        
        return {
            "deviceType": "ECG",
            "timestamp": self.get_timestamp(),
            "heartRate": round(heart_rate, 1),
            "ecgWaveform": round(ecg_value, 3),
            "rhythm": "Normal Sinus Rhythm",
            "alertLevel": "Normal"
        }
    
    def infusion_pump_data(self) -> Dict[str, Any]:
        """Generate infusion pump data"""
        flow_rate = 50 + random.gauss(0, 2)  # 50±2 mL/hr
        pressure = 15 + random.gauss(0, 1)   # 15±1 PSI
        volume_infused = random.uniform(100, 500)
        
        return {
            "deviceType": "InfusionPump",
            "timestamp": self.get_timestamp(),
            "flowRate": round(flow_rate, 1),
            "pressure": round(pressure, 1),
            "volumeInfused": round(volume_infused, 1),
            "batteryLevel": random.randint(75, 100),
            "status": "Active"
        }
    
    def pulse_oximeter_data(self) -> Dict[str, Any]:
        """Generate pulse oximeter data"""
        spo2 = 97 + random.gauss(0, 1.5)  # 97±1.5%
        pulse_rate = 72 + random.gauss(0, 8)  # 72±8 BPM
        
        return {
            "deviceType": "PulseOximeter",
            "timestamp": self.get_timestamp(),
            "oxygenSaturation": round(max(min(spo2, 100), 85), 1),
            "pulseRate": round(max(pulse_rate, 50), 1),
            "perfusionIndex": round(random.uniform(1.5, 8.0), 2),
            "signalQuality": random.choice(["Excellent", "Good", "Fair"])
        }
    
    def ventilator_data(self) -> Dict[str, Any]:
        """Generate ventilator data"""
        tidal_volume = 450 + random.gauss(0, 20)  # 450±20 mL
        resp_rate = 16 + random.gauss(0, 2)       # 16±2 breaths/min
        peep = 5 + random.gauss(0, 0.5)           # 5±0.5 cmH2O
        
        return {
            "deviceType": "Ventilator",
            "timestamp": self.get_timestamp(),
            "tidalVolume": round(tidal_volume, 0),
            "respiratoryRate": round(resp_rate, 1),
            "peep": round(peep, 1),
            "inspiratoryPressure": round(20 + random.gauss(0, 2), 1),
            "fio2": round(0.21 + random.uniform(0, 0.79), 2),
            "mode": "Volume Control"
        }
    
    def blood_pressure_data(self) -> Dict[str, Any]:
        """Generate blood pressure monitor data"""
        systolic = 120 + random.gauss(0, 15)
        diastolic = 80 + random.gauss(0, 10)
        
        return {
            "deviceType": "BloodPressureMonitor",
            "timestamp": self.get_timestamp(),
            "systolic": round(max(systolic, 90), 0),
            "diastolic": round(max(diastolic, 60), 0),
            "meanArterialPressure": round((systolic + 2 * diastolic) / 3, 1),
            "pulseRate": round(70 + random.gauss(0, 10), 0),
            "cuffPressure": round(random.uniform(0, 200), 1)
        }
    
    def glucometer_data(self) -> Dict[str, Any]:
        """Generate glucometer data"""
        glucose = 100 + random.gauss(0, 20)  # 100±20 mg/dL
        
        return {
            "deviceType": "Glucometer",
            "timestamp": self.get_timestamp(),
            "glucoseLevel": round(max(glucose, 60), 1),
            "unit": "mg/dL",
            "testStrip": "Used",
            "batteryLevel": random.randint(60, 100),
            "temperature": round(20 + random.gauss(0, 2), 1)
        }
    
    def thermometer_data(self) -> Dict[str, Any]:
        """Generate thermometer data"""
        temp_c = 37.0 + random.gauss(0, 0.5)  # 37±0.5°C
        temp_f = temp_c * 9/5 + 32
        
        return {
            "deviceType": "Thermometer",
            "timestamp": self.get_timestamp(),
            "temperatureCelsius": round(temp_c, 2),
            "temperatureFahrenheit": round(temp_f, 2),
            "measurementSite": random.choice(["Oral", "Ear", "Forehead", "Axillary"]),
            "batteryLevel": random.randint(70, 100)
        }
    
    def defibrillator_data(self) -> Dict[str, Any]:
        """Generate defibrillator data"""
        return {
            "deviceType": "Defibrillator",
            "timestamp": self.get_timestamp(),
            "batteryLevel": random.randint(80, 100),
            "padConnection": "Connected",
            "lastSelfTest": "Passed",
            "shockEnergy": random.choice([150, 200, 300, 360]),
            "status": random.choice(["Ready", "Monitoring", "Standby"]),
            "impedance": round(random.uniform(40, 120), 0)
        }
    
    def eeg_data(self) -> Dict[str, Any]:
        """Generate EEG data"""
        # Simulate basic brain wave patterns
        alpha_wave = random.uniform(8, 13)  # 8-13 Hz
        beta_wave = random.uniform(13, 30)  # 13-30 Hz
        
        return {
            "deviceType": "EEG",
            "timestamp": self.get_timestamp(),
            "alphaWave": round(alpha_wave, 2),
            "betaWave": round(beta_wave, 2),
            "amplitude": round(random.uniform(10, 100), 2),
            "impedance": round(random.uniform(1, 10), 1),
            "electrodeStatus": "Good Contact",
            "artifacts": random.choice(["None", "Eye Blink", "Muscle"])
        }
    
    def ultrasound_data(self) -> Dict[str, Any]:
        """Generate ultrasound data"""
        return {
            "deviceType": "Ultrasound",
            "timestamp": self.get_timestamp(),
            "frequency": round(random.uniform(2.0, 15.0), 1),
            "depth": round(random.uniform(5, 25), 1),
            "gain": random.randint(40, 80),
            "mode": random.choice(["B-Mode", "M-Mode", "Doppler"]),
            "temperature": round(20 + random.gauss(0, 2), 1),
            "probeConnected": True
        }
    
    def generate_data(self, device_type: str) -> Dict[str, Any]:
        """Generate telemetry data based on device type"""
        generators = {
            "ECG": self.ecg_data,
            "InfusionPump": self.infusion_pump_data,
            "PulseOximeter": self.pulse_oximeter_data,
            "Ventilator": self.ventilator_data,
            "BloodPressureMonitor": self.blood_pressure_data,
            "Glucometer": self.glucometer_data,
            "Thermometer": self.thermometer_data,
            "Defibrillator": self.defibrillator_data,
            "EEG": self.eeg_data,
            "Ultrasound": self.ultrasound_data
        }
        
        generator = generators.get(device_type)
        if generator:
            self.time_offset += 0.1  # Slight time offset for variety
            return generator()
        else:
            return {
                "deviceType": device_type,
                "timestamp": self.get_timestamp(),
                "error": f"Unknown device type: {device_type}"
            }


class TelemetryClient:
    """Manages telemetry sending for multiple devices"""
    
    def __init__(self, devices_file: str = "output/devices.json"):
        self.devices_file = Path(devices_file)
        self.devices: List[Dict] = []
        self.clients: Dict[str, IoTHubDeviceClient] = {}
        self.data_generator = MedicalDataGenerator()
        
    def load_devices(self) -> None:
        """Load device information from JSON file"""
        try:
            with self.devices_file.open('r') as f:
                self.devices = json.load(f)
            print(f"Loaded {len(self.devices)} devices from {self.devices_file}")
        except FileNotFoundError:
            raise SystemExit(f"Device file not found: {self.devices_file}")
        except json.JSONDecodeError as e:
            raise SystemExit(f"Invalid JSON in device file: {e}")
    
    async def connect_devices(self, device_filter: Optional[List[str]] = None) -> None:
        """Connect to IoT Hub for selected devices"""
        devices_to_connect = self.devices
        if device_filter:
            devices_to_connect = [d for d in self.devices if d['deviceId'] in device_filter]
        
        print(f"Connecting {len(devices_to_connect)} devices...")
        
        for device in devices_to_connect:
            device_id = device['deviceId']
            connection_string = device['connectionString']
            
            try:
                client = IoTHubDeviceClient.create_from_connection_string(connection_string)
                await client.connect()
                self.clients[device_id] = client
                print(f"✓ Connected: {device_id}")
            except Exception as e:
                print(f"✗ Failed to connect {device_id}: {e}")
    
    async def send_telemetry_batch(self, message_count: int = 1) -> None:
        """Send telemetry messages from all connected devices"""
        if not self.clients:
            print("No devices connected")
            return
        
        tasks = []
        for device_id, client in self.clients.items():
            # Find device info
            device_info = next(d for d in self.devices if d['deviceId'] == device_id)
            device_type = device_info['deviceType']
            
            # Create task for sending messages
            task = self.send_device_messages(client, device_id, device_type, message_count)
            tasks.append(task)
        
        # Send all messages concurrently
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def send_device_messages(self, client: IoTHubDeviceClient, device_id: str, 
                                   device_type: str, message_count: int) -> None:
        """Send messages for a specific device"""
        try:
            for i in range(message_count):
                # Generate telemetry data
                telemetry_data = self.data_generator.generate_data(device_type)
                telemetry_data['deviceId'] = device_id
                
                # Create and send message
                message = Message(json.dumps(telemetry_data))
                message.content_encoding = "utf-8"
                message.content_type = "application/json"
                
                # Add custom properties
                message.custom_properties["deviceType"] = device_type
                message.custom_properties["messageType"] = "telemetry"
                
                await client.send_message(message)
                print(f"📊 {device_id}: Sent {device_type} telemetry")
                
                if message_count > 1:
                    await asyncio.sleep(0.1)  # Small delay between messages
                    
        except Exception as e:
            print(f"✗ Error sending from {device_id}: {e}")
    
    async def run_continuous(self, interval: float, duration: Optional[float] = None) -> None:
        """Send telemetry continuously at specified intervals"""
        start_time = time.time()
        message_count = 0
        
        print(f"\n🚀 Starting continuous telemetry (interval: {interval}s)")
        if duration:
            print(f"Duration: {duration}s")
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                if duration and (time.time() - start_time) >= duration:
                    break
                
                await self.send_telemetry_batch(1)
                message_count += len(self.clients)
                
                print(f"Sent batch #{message_count // len(self.clients)} "
                      f"({message_count} total messages)")
                
                await asyncio.sleep(interval)
                
        except KeyboardInterrupt:
            print("\n⏹️ Stopped by user")
        
        elapsed = time.time() - start_time
        print(f"\n📈 Summary: {message_count} messages sent in {elapsed:.1f}s")
    
    async def disconnect_all(self) -> None:
        """Disconnect all devices"""
        print("\nDisconnecting devices...")
        for device_id, client in self.clients.items():
            try:
                await client.disconnect()
                print(f"✓ Disconnected: {device_id}")
            except Exception as e:
                print(f"✗ Error disconnecting {device_id}: {e}")


async def main():
    parser = argparse.ArgumentParser(
        description="Send mock telemetry data to Azure IoT Hub from medical devices"
    )
    parser.add_argument(
        "--devices-file",
        default="output/devices.json",
        help="Path to devices JSON file (default: output/devices.json)"
    )
    parser.add_argument(
        "--device-ids",
        help="Comma-separated list of device IDs to use (default: all)"
    )
    parser.add_argument(
        "--messages",
        type=int,
        default=5,
        help="Number of messages per device for batch mode (default: 5)"
    )
    parser.add_argument(
        "--continuous",
        action="store_true",
        help="Send messages continuously"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=10.0,
        help="Interval between messages in continuous mode (default: 10.0s)"
    )
    parser.add_argument(
        "--duration",
        type=float,
        help="Duration for continuous mode in seconds (default: infinite)"
    )
    args = parser.parse_args()
    
    # Parse device filter
    device_filter = None
    if args.device_ids:
        device_filter = [d.strip() for d in args.device_ids.split(',')]
    
    # Initialize telemetry client
    client = TelemetryClient(args.devices_file)
    client.load_devices()
    
    try:
        # Connect to devices
        await client.connect_devices(device_filter)
        
        if not client.clients:
            print("No devices connected. Exiting.")
            return
        
        # Send telemetry
        if args.continuous:
            await client.run_continuous(args.interval, args.duration)
        else:
            print(f"\n📤 Sending {args.messages} messages per device...")
            await client.send_telemetry_batch(args.messages)
            print(f"\n✅ Sent {args.messages * len(client.clients)} total messages")
        
    finally:
        # Clean up
        await client.disconnect_all()


if __name__ == "__main__":
    asyncio.run(main())