#!/usr/bin/env python3
"""
Sample telemetry data viewer - shows what data is being sent
"""
import json
from telemetry_client import MedicalDataGenerator

def main():
    generator = MedicalDataGenerator()
    
    print("🏥 Sample Medical Device Telemetry Data\n")
    print("=" * 60)
    
    device_types = [
        "ECG", "PulseOximeter", "BloodPressureMonitor", 
        "InfusionPump", "Ventilator", "Glucometer",
        "Thermometer", "Defibrillator", "EEG", "Ultrasound"
    ]
    
    for device_type in device_types:
        print(f"\n📊 {device_type}:")
        print("-" * 40)
        data = generator.generate_data(device_type)
        print(json.dumps(data, indent=2))

if __name__ == "__main__":
    main()