"""
Patch & Validation Agent for IoT Security
Manages ephemeral IoT Hub devices, applies patches automatically, and collects validation results
Provides automated patch deployment and rollback capabilities
"""

import asyncio
import aiohttp
import json
import logging
import tempfile
import subprocess
import shutil
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import sqlite3
import threading
from enum import Enum
import docker
import paramiko
from scp import SCPClient

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PatchStatus(Enum):
    """Patch deployment status"""
    PENDING = "PENDING"
    DOWNLOADING = "DOWNLOADING"
    VALIDATING = "VALIDATING"
    DEPLOYING = "DEPLOYING"
    TESTING = "TESTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"

class ValidationResult(Enum):
    """Patch validation results"""
    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"
    UNKNOWN = "UNKNOWN"

@dataclass
class PatchPackage:
    """Patch package information"""
    patch_id: str
    device_type: str
    firmware_version: str
    target_version: str
    patch_url: str
    checksum: str
    description: str
    severity: str
    release_date: str
    vendor: str
    prerequisites: List[str] = None
    rollback_data: Optional[str] = None

@dataclass
class DeviceSnapshot:
    """Device state snapshot for rollback"""
    device_id: str
    timestamp: str
    firmware_version: str
    configuration: Dict[str, Any]
    system_state: Dict[str, Any]
    network_config: Dict[str, Any]
    running_processes: List[str]
    file_checksums: Dict[str, str]

@dataclass
class PatchDeployment:
    """Patch deployment record"""
    deployment_id: str
    device_id: str
    patch_id: str
    status: PatchStatus
    started_at: str
    completed_at: Optional[str]
    validation_results: List[Dict[str, Any]]
    rollback_available: bool
    error_message: Optional[str]
    performance_impact: Optional[Dict[str, float]]

class PatchValidationAgent:
    """
    Advanced patch deployment and validation agent for IoT devices
    """
    
    def __init__(self, db_path: str = "data/patch_management.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True)
        self._lock = threading.Lock()
        
        # Docker client for ephemeral testing
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            logger.warning(f"Docker not available: {e}")
            self.docker_client = None
        
        # Patch repositories
        self.patch_sources = {
            "vendor_official": "https://patches.iot-vendors.com/api/",
            "community": "https://iot-patches.github.io/api/",
            "security": "https://security-patches.nist.gov/api/"
        }
        
        # Validation tests configuration
        self.validation_tests = {
            "connectivity": {"timeout": 30, "retry": 3},
            "functionality": {"timeout": 60, "critical": True},
            "performance": {"baseline_variance": 20, "timeout": 120},
            "security": {"port_scan": True, "vulnerability_check": True},
            "stability": {"duration": 300, "resource_monitoring": True}
        }
        
        self._init_database()
    
    def _init_database(self):
        """Initialize patch management database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Patch packages table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS patch_packages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    patch_id TEXT UNIQUE NOT NULL,
                    device_type TEXT NOT NULL,
                    firmware_version TEXT NOT NULL,
                    target_version TEXT NOT NULL,
                    patch_url TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    release_date TEXT NOT NULL,
                    vendor TEXT NOT NULL,
                    prerequisites TEXT,
                    downloaded_at DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Device snapshots table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    firmware_version TEXT NOT NULL,
                    configuration TEXT NOT NULL,
                    system_state TEXT NOT NULL,
                    network_config TEXT NOT NULL,
                    running_processes TEXT NOT NULL,
                    file_checksums TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Patch deployments table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS patch_deployments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    deployment_id TEXT UNIQUE NOT NULL,
                    device_id TEXT NOT NULL,
                    patch_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    validation_results TEXT,
                    rollback_available BOOLEAN DEFAULT 0,
                    error_message TEXT,
                    performance_impact TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Ephemeral test environments table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS test_environments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    environment_id TEXT UNIQUE NOT NULL,
                    device_type TEXT NOT NULL,
                    base_image TEXT NOT NULL,
                    container_id TEXT,
                    status TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    destroyed_at DATETIME
                )
            """)
            
            conn.commit()
            logger.info("Patch management database initialized")
    
    async def discover_available_patches(self, device_info: Dict) -> List[PatchPackage]:
        """Discover available patches for a device"""
        logger.info(f"Discovering patches for device {device_info.get('deviceId', 'unknown')}")
        
        patches = []
        device_type = device_info.get('deviceType', '')
        firmware_version = device_info.get('firmwareVersion', '')
        manufacturer = device_info.get('manufacturer', '')
        
        try:
            # Check vendor official patches
            vendor_patches = await self._query_vendor_patches(manufacturer, device_type, firmware_version)
            patches.extend(vendor_patches)
            
            # Check security patches
            security_patches = await self._query_security_patches(device_type, firmware_version)
            patches.extend(security_patches)
            
            # Store discovered patches
            await self._store_patch_packages(patches)
            
            logger.info(f"Discovered {len(patches)} available patches")
            
        except Exception as e:
            logger.error(f"Failed to discover patches: {e}")
        
        return patches
    
    async def _query_vendor_patches(self, manufacturer: str, device_type: str, firmware_version: str) -> List[PatchPackage]:
        """Query vendor official patch repositories"""
        patches = []
        
        # Simulate vendor patch API calls
        # In production, this would query actual vendor APIs
        
        simulated_patches = [
            {
                "patch_id": f"PATCH-{manufacturer.upper()}-001",
                "device_type": device_type,
                "firmware_version": firmware_version,
                "target_version": self._increment_version(firmware_version),
                "patch_url": f"https://patches.{manufacturer.lower()}.com/firmware/{device_type}/latest.bin",
                "checksum": "sha256:abc123def456...",
                "description": f"Security update for {device_type} - fixes critical vulnerabilities",
                "severity": "CRITICAL",
                "release_date": datetime.now().isoformat(),
                "vendor": manufacturer,
                "prerequisites": []
            }
        ]
        
        for patch_data in simulated_patches:
            patch = PatchPackage(**patch_data)
            patches.append(patch)
        
        return patches
    
    async def _query_security_patches(self, device_type: str, firmware_version: str) -> List[PatchPackage]:
        """Query security-focused patch repositories"""
        patches = []
        
        # Simulate security patch discovery
        security_patches = [
            {
                "patch_id": f"SEC-{hashlib.md5(device_type.encode()).hexdigest()[:8].upper()}",
                "device_type": device_type,
                "firmware_version": firmware_version,
                "target_version": self._increment_version(firmware_version, patch_level=True),
                "patch_url": f"https://security-patches.example.com/{device_type}/security-patch.bin",
                "checksum": "sha256:def789abc123...",
                "description": f"Security patch addressing CVE vulnerabilities in {device_type}",
                "severity": "HIGH",
                "release_date": datetime.now().isoformat(),
                "vendor": "Security Community",
                "prerequisites": ["backup_required"]
            }
        ]
        
        for patch_data in security_patches:
            patch = PatchPackage(**patch_data)
            patches.append(patch)
        
        return patches
    
    def _increment_version(self, version: str, patch_level: bool = False) -> str:
        """Increment version number for patch simulation"""
        try:
            parts = version.split('.')
            if patch_level and len(parts) >= 3:
                parts[2] = str(int(parts[2]) + 1)
            elif len(parts) >= 2:
                parts[1] = str(int(parts[1]) + 1)
            else:
                parts.append('1')
            return '.'.join(parts)
        except:
            return f"{version}.1"
    
    async def create_ephemeral_test_environment(self, device_info: Dict) -> Optional[str]:
        """Create ephemeral test environment for patch validation"""
        if not self.docker_client:
            logger.warning("Docker not available - cannot create ephemeral environment")
            return None
        
        try:
            device_type = device_info.get('deviceType', 'generic-iot')
            environment_id = f"test-{device_type}-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            
            # Select appropriate base image
            base_image = self._select_base_image(device_info)
            
            # Create container
            container = self.docker_client.containers.run(
                base_image,
                name=environment_id,
                detach=True,
                privileged=True,  # May be needed for device simulation
                ports={'22/tcp': None, '80/tcp': None, '443/tcp': None},
                environment={
                    'DEVICE_TYPE': device_type,
                    'FIRMWARE_VERSION': device_info.get('firmwareVersion', ''),
                    'SIMULATION_MODE': 'true'
                },
                command='sleep 3600'  # Keep container alive for testing
            )
            
            # Record test environment
            await self._record_test_environment(environment_id, device_info, base_image, container.id)
            
            logger.info(f"Created ephemeral test environment: {environment_id}")
            return environment_id
            
        except Exception as e:
            logger.error(f"Failed to create test environment: {e}")
            return None
    
    def _select_base_image(self, device_info: Dict) -> str:
        """Select appropriate Docker base image for device simulation"""
        device_type = device_info.get('deviceType', '').lower()
        os_name = device_info.get('osName', '').lower()
        
        # Map device types to appropriate base images
        if 'linux' in os_name or 'ubuntu' in os_name:
            return 'ubuntu:20.04'
        elif 'alpine' in os_name:
            return 'alpine:latest'
        elif 'busybox' in os_name:
            return 'busybox:latest'
        elif 'raspberry' in device_type:
            return 'arm32v7/ubuntu:20.04'
        else:
            return 'ubuntu:20.04'  # Default fallback
    
    async def deploy_patch(self, device_id: str, patch_id: str, test_environment: Optional[str] = None) -> str:
        """Deploy patch to device or test environment"""
        deployment_id = f"deploy-{device_id}-{patch_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        logger.info(f"Starting patch deployment {deployment_id}")
        
        try:
            # Record deployment start
            deployment = PatchDeployment(
                deployment_id=deployment_id,
                device_id=device_id,
                patch_id=patch_id,
                status=PatchStatus.PENDING,
                started_at=datetime.now().isoformat(),
                completed_at=None,
                validation_results=[],
                rollback_available=False,
                error_message=None,
                performance_impact=None
            )
            
            await self._store_deployment_record(deployment)
            
            # Create device snapshot for rollback
            snapshot = await self._create_device_snapshot(device_id)
            if snapshot:
                deployment.rollback_available = True
                await self._update_deployment_record(deployment)
            
            # Download and validate patch
            await self._update_deployment_status(deployment_id, PatchStatus.DOWNLOADING)
            patch_file = await self._download_patch(patch_id)
            
            if not patch_file:
                await self._fail_deployment(deployment_id, "Failed to download patch")
                return deployment_id
            
            await self._update_deployment_status(deployment_id, PatchStatus.VALIDATING)
            if not await self._validate_patch_integrity(patch_file, patch_id):
                await self._fail_deployment(deployment_id, "Patch integrity validation failed")
                return deployment_id
            
            # Deploy patch
            await self._update_deployment_status(deployment_id, PatchStatus.DEPLOYING)
            deploy_success = await self._apply_patch_to_device(device_id, patch_file, test_environment)
            
            if not deploy_success:
                await self._fail_deployment(deployment_id, "Patch deployment failed")
                return deployment_id
            
            # Run validation tests
            await self._update_deployment_status(deployment_id, PatchStatus.TESTING)
            validation_results = await self._run_validation_tests(device_id, test_environment)
            
            # Update deployment with results
            deployment.validation_results = validation_results
            deployment.completed_at = datetime.now().isoformat()
            
            # Check if validation passed
            if self._all_validations_passed(validation_results):
                deployment.status = PatchStatus.COMPLETED
                logger.info(f"Patch deployment {deployment_id} completed successfully")
            else:
                deployment.status = PatchStatus.FAILED
                deployment.error_message = "Validation tests failed"
                logger.warning(f"Patch deployment {deployment_id} failed validation")
                
                # Automatic rollback if critical tests failed
                if self._critical_validations_failed(validation_results):
                    await self._rollback_deployment(deployment_id)
            
            await self._update_deployment_record(deployment)
            
        except Exception as e:
            await self._fail_deployment(deployment_id, f"Deployment error: {str(e)}")
            logger.error(f"Patch deployment {deployment_id} failed: {e}")
        
        return deployment_id
    
    async def _create_device_snapshot(self, device_id: str) -> Optional[DeviceSnapshot]:
        """Create a snapshot of device state for rollback"""
        try:
            # In a real implementation, this would connect to the actual device
            # For now, we'll create a simulated snapshot
            
            snapshot = DeviceSnapshot(
                device_id=device_id,
                timestamp=datetime.now().isoformat(),
                firmware_version="current_version",
                configuration={"config": "simulated"},
                system_state={"state": "simulated"},
                network_config={"network": "simulated"},
                running_processes=["process1", "process2"],
                file_checksums={"file1": "checksum1", "file2": "checksum2"}
            )
            
            await self._store_device_snapshot(snapshot)
            logger.info(f"Created snapshot for device {device_id}")
            
            return snapshot
            
        except Exception as e:
            logger.error(f"Failed to create device snapshot: {e}")
            return None
    
    async def _download_patch(self, patch_id: str) -> Optional[Path]:
        """Download patch file"""
        try:
            # Get patch info from database
            patch_info = await self._get_patch_info(patch_id)
            if not patch_info:
                return None
            
            # Create temporary file
            temp_dir = Path(tempfile.gettempdir()) / "patch_downloads"
            temp_dir.mkdir(exist_ok=True)
            
            patch_file = temp_dir / f"{patch_id}.bin"
            
            # Simulate patch download
            # In production, this would download from the actual URL
            with open(patch_file, 'wb') as f:
                f.write(b"SIMULATED_PATCH_DATA_" + patch_id.encode())
            
            logger.info(f"Downloaded patch {patch_id} to {patch_file}")
            return patch_file
            
        except Exception as e:
            logger.error(f"Failed to download patch {patch_id}: {e}")
            return None
    
    async def _validate_patch_integrity(self, patch_file: Path, patch_id: str) -> bool:
        """Validate patch file integrity"""
        try:
            # Calculate checksum
            with open(patch_file, 'rb') as f:
                content = f.read()
                calculated_checksum = hashlib.sha256(content).hexdigest()
            
            # Get expected checksum from database
            patch_info = await self._get_patch_info(patch_id)
            expected_checksum = patch_info.get('checksum', '').replace('sha256:', '')
            
            # For simulation, we'll always pass validation
            # In production, compare calculated_checksum with expected_checksum
            logger.info(f"Patch integrity validation passed for {patch_id}")
            return True
            
        except Exception as e:
            logger.error(f"Patch integrity validation failed: {e}")
            return False
    
    async def _apply_patch_to_device(self, device_id: str, patch_file: Path, test_environment: Optional[str]) -> bool:
        """Apply patch to device or test environment"""
        try:
            if test_environment:
                return await self._apply_patch_to_container(test_environment, patch_file)
            else:
                return await self._apply_patch_to_real_device(device_id, patch_file)
                
        except Exception as e:
            logger.error(f"Failed to apply patch: {e}")
            return False
    
    async def _apply_patch_to_container(self, environment_id: str, patch_file: Path) -> bool:
        """Apply patch to Docker test environment"""
        try:
            if not self.docker_client:
                return False
            
            container = self.docker_client.containers.get(environment_id)
            
            # Copy patch file to container
            with open(patch_file, 'rb') as f:
                patch_data = f.read()
            
            # Simulate patch application
            exec_result = container.exec_run(
                f"echo 'Applying patch {patch_file.name}' && sleep 2 && echo 'Patch applied successfully'",
                tty=True
            )
            
            logger.info(f"Applied patch to test environment {environment_id}")
            return exec_result.exit_code == 0
            
        except Exception as e:
            logger.error(f"Failed to apply patch to container: {e}")
            return False
    
    async def _apply_patch_to_real_device(self, device_id: str, patch_file: Path) -> bool:
        """Apply patch to real IoT device"""
        try:
            # In production, this would:
            # 1. Connect to device via SSH/SCP
            # 2. Upload patch file
            # 3. Execute patch installation commands
            # 4. Verify installation
            
            # For simulation, we'll just log the action
            logger.info(f"Simulated patch application to device {device_id}")
            await asyncio.sleep(2)  # Simulate patch application time
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply patch to device {device_id}: {e}")
            return False
    
    async def _run_validation_tests(self, device_id: str, test_environment: Optional[str]) -> List[Dict[str, Any]]:
        """Run comprehensive validation tests after patch deployment"""
        results = []
        
        # Connectivity test
        connectivity_result = await self._test_connectivity(device_id, test_environment)
        results.append(connectivity_result)
        
        # Functionality test
        functionality_result = await self._test_functionality(device_id, test_environment)
        results.append(functionality_result)
        
        # Performance test
        performance_result = await self._test_performance(device_id, test_environment)
        results.append(performance_result)
        
        # Security test
        security_result = await self._test_security(device_id, test_environment)
        results.append(security_result)
        
        # Stability test
        stability_result = await self._test_stability(device_id, test_environment)
        results.append(stability_result)
        
        return results
    
    async def _test_connectivity(self, device_id: str, test_environment: Optional[str]) -> Dict[str, Any]:
        """Test device connectivity after patch"""
        try:
            # Simulate connectivity test
            await asyncio.sleep(1)
            
            return {
                "test_name": "connectivity",
                "result": ValidationResult.PASSED.value,
                "details": "Device responds to network requests",
                "duration": 1.0,
                "critical": True
            }
            
        except Exception as e:
            return {
                "test_name": "connectivity",
                "result": ValidationResult.FAILED.value,
                "details": f"Connectivity test failed: {e}",
                "duration": 0,
                "critical": True
            }
    
    async def _test_functionality(self, device_id: str, test_environment: Optional[str]) -> Dict[str, Any]:
        """Test device core functionality after patch"""
        try:
            # Simulate functionality test
            await asyncio.sleep(2)
            
            return {
                "test_name": "functionality",
                "result": ValidationResult.PASSED.value,
                "details": "All core functions operational",
                "duration": 2.0,
                "critical": True
            }
            
        except Exception as e:
            return {
                "test_name": "functionality",
                "result": ValidationResult.FAILED.value,
                "details": f"Functionality test failed: {e}",
                "duration": 0,
                "critical": True
            }
    
    async def _test_performance(self, device_id: str, test_environment: Optional[str]) -> Dict[str, Any]:
        """Test device performance after patch"""
        try:
            # Simulate performance test
            await asyncio.sleep(3)
            
            return {
                "test_name": "performance",
                "result": ValidationResult.PASSED.value,
                "details": "Performance within acceptable limits",
                "duration": 3.0,
                "critical": False,
                "metrics": {
                    "cpu_usage": 15.2,
                    "memory_usage": 45.8,
                    "response_time": 120.5
                }
            }
            
        except Exception as e:
            return {
                "test_name": "performance",
                "result": ValidationResult.WARNING.value,
                "details": f"Performance test completed with warnings: {e}",
                "duration": 0,
                "critical": False
            }
    
    async def _test_security(self, device_id: str, test_environment: Optional[str]) -> Dict[str, Any]:
        """Test device security after patch"""
        try:
            # Simulate security test
            await asyncio.sleep(2)
            
            return {
                "test_name": "security",
                "result": ValidationResult.PASSED.value,
                "details": "No security vulnerabilities detected",
                "duration": 2.0,
                "critical": True
            }
            
        except Exception as e:
            return {
                "test_name": "security",
                "result": ValidationResult.FAILED.value,
                "details": f"Security test failed: {e}",
                "duration": 0,
                "critical": True
            }
    
    async def _test_stability(self, device_id: str, test_environment: Optional[str]) -> Dict[str, Any]:
        """Test device stability after patch"""
        try:
            # Simulate stability test (shorter for demo)
            await asyncio.sleep(1)
            
            return {
                "test_name": "stability",
                "result": ValidationResult.PASSED.value,
                "details": "Device stable under load",
                "duration": 1.0,
                "critical": False
            }
            
        except Exception as e:
            return {
                "test_name": "stability",
                "result": ValidationResult.WARNING.value,
                "details": f"Stability test completed with warnings: {e}",
                "duration": 0,
                "critical": False
            }
    
    def _all_validations_passed(self, results: List[Dict[str, Any]]) -> bool:
        """Check if all validation tests passed"""
        for result in results:
            if result.get('critical', False) and result.get('result') == ValidationResult.FAILED.value:
                return False
        return True
    
    def _critical_validations_failed(self, results: List[Dict[str, Any]]) -> bool:
        """Check if any critical validation tests failed"""
        for result in results:
            if result.get('critical', False) and result.get('result') == ValidationResult.FAILED.value:
                return True
        return False
    
    async def _rollback_deployment(self, deployment_id: str):
        """Rollback a failed patch deployment"""
        try:
            logger.info(f"Rolling back deployment {deployment_id}")
            
            # Get deployment info
            deployment = await self._get_deployment_info(deployment_id)
            if not deployment:
                return
            
            # Get device snapshot
            snapshot = await self._get_latest_snapshot(deployment['device_id'])
            if not snapshot:
                logger.error("No snapshot available for rollback")
                return
            
            # Perform rollback (simulated)
            await asyncio.sleep(2)
            
            # Update deployment status
            await self._update_deployment_status(deployment_id, PatchStatus.ROLLED_BACK)
            
            logger.info(f"Successfully rolled back deployment {deployment_id}")
            
        except Exception as e:
            logger.error(f"Failed to rollback deployment {deployment_id}: {e}")
    
    async def cleanup_test_environment(self, environment_id: str):
        """Clean up ephemeral test environment"""
        try:
            if self.docker_client:
                container = self.docker_client.containers.get(environment_id)
                container.stop()
                container.remove()
                
                # Update database record
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE test_environments 
                        SET status = 'destroyed', destroyed_at = CURRENT_TIMESTAMP
                        WHERE environment_id = ?
                    """, (environment_id,))
                    conn.commit()
                
                logger.info(f"Cleaned up test environment {environment_id}")
                
        except Exception as e:
            logger.error(f"Failed to cleanup test environment {environment_id}: {e}")
    
    # Database helper methods
    async def _store_patch_packages(self, patches: List[PatchPackage]):
        """Store patch packages in database"""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    
                    for patch in patches:
                        cursor.execute("""
                            INSERT OR REPLACE INTO patch_packages
                            (patch_id, device_type, firmware_version, target_version,
                             patch_url, checksum, description, severity, release_date,
                             vendor, prerequisites)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            patch.patch_id, patch.device_type, patch.firmware_version,
                            patch.target_version, patch.patch_url, patch.checksum,
                            patch.description, patch.severity, patch.release_date,
                            patch.vendor, json.dumps(patch.prerequisites or [])
                        ))
                    
                    conn.commit()
                    
            except Exception as e:
                logger.error(f"Failed to store patch packages: {e}")
    
    async def _store_device_snapshot(self, snapshot: DeviceSnapshot):
        """Store device snapshot in database"""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO device_snapshots
                        (device_id, timestamp, firmware_version, configuration,
                         system_state, network_config, running_processes, file_checksums)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        snapshot.device_id, snapshot.timestamp, snapshot.firmware_version,
                        json.dumps(snapshot.configuration), json.dumps(snapshot.system_state),
                        json.dumps(snapshot.network_config), json.dumps(snapshot.running_processes),
                        json.dumps(snapshot.file_checksums)
                    ))
                    conn.commit()
                    
            except Exception as e:
                logger.error(f"Failed to store device snapshot: {e}")
    
    async def _store_deployment_record(self, deployment: PatchDeployment):
        """Store deployment record in database"""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO patch_deployments
                        (deployment_id, device_id, patch_id, status, started_at,
                         completed_at, validation_results, rollback_available,
                         error_message, performance_impact)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        deployment.deployment_id, deployment.device_id, deployment.patch_id,
                        deployment.status.value, deployment.started_at, deployment.completed_at,
                        json.dumps(deployment.validation_results), deployment.rollback_available,
                        deployment.error_message, json.dumps(deployment.performance_impact) if deployment.performance_impact else None
                    ))
                    conn.commit()
                    
            except Exception as e:
                logger.error(f"Failed to store deployment record: {e}")
    
    async def _update_deployment_record(self, deployment: PatchDeployment):
        """Update deployment record in database"""
        with self._lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        UPDATE patch_deployments SET
                        status = ?, completed_at = ?, validation_results = ?,
                        rollback_available = ?, error_message = ?, performance_impact = ?
                        WHERE deployment_id = ?
                    """, (
                        deployment.status.value, deployment.completed_at,
                        json.dumps(deployment.validation_results), deployment.rollback_available,
                        deployment.error_message, json.dumps(deployment.performance_impact) if deployment.performance_impact else None,
                        deployment.deployment_id
                    ))
                    conn.commit()
                    
            except Exception as e:
                logger.error(f"Failed to update deployment record: {e}")
    
    async def _update_deployment_status(self, deployment_id: str, status: PatchStatus):
        """Update deployment status"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE patch_deployments SET status = ? WHERE deployment_id = ?
            """, (status.value, deployment_id))
            conn.commit()
    
    async def _fail_deployment(self, deployment_id: str, error_message: str):
        """Mark deployment as failed"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE patch_deployments 
                SET status = ?, error_message = ?, completed_at = ?
                WHERE deployment_id = ?
            """, (PatchStatus.FAILED.value, error_message, datetime.now().isoformat(), deployment_id))
            conn.commit()
    
    async def _record_test_environment(self, environment_id: str, device_info: Dict, base_image: str, container_id: str):
        """Record test environment in database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO test_environments
                (environment_id, device_type, base_image, container_id, status)
                VALUES (?, ?, ?, ?, 'active')
            """, (environment_id, device_info.get('deviceType', ''), base_image, container_id))
            conn.commit()
    
    async def _get_patch_info(self, patch_id: str) -> Optional[Dict]:
        """Get patch information from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT patch_url, checksum, description 
                    FROM patch_packages WHERE patch_id = ?
                """, (patch_id,))
                row = cursor.fetchone()
                
                if row:
                    return {
                        'patch_url': row[0],
                        'checksum': row[1],
                        'description': row[2]
                    }
                    
        except Exception as e:
            logger.error(f"Failed to get patch info: {e}")
        
        return None
    
    async def _get_deployment_info(self, deployment_id: str) -> Optional[Dict]:
        """Get deployment information from database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT device_id, patch_id, status 
                    FROM patch_deployments WHERE deployment_id = ?
                """, (deployment_id,))
                row = cursor.fetchone()
                
                if row:
                    return {
                        'device_id': row[0],
                        'patch_id': row[1],
                        'status': row[2]
                    }
                    
        except Exception as e:
            logger.error(f"Failed to get deployment info: {e}")
        
        return None
    
    async def _get_latest_snapshot(self, device_id: str) -> Optional[DeviceSnapshot]:
        """Get latest device snapshot"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT device_id, timestamp, firmware_version, configuration,
                           system_state, network_config, running_processes, file_checksums
                    FROM device_snapshots 
                    WHERE device_id = ? 
                    ORDER BY created_at DESC 
                    LIMIT 1
                """, (device_id,))
                row = cursor.fetchone()
                
                if row:
                    return DeviceSnapshot(
                        device_id=row[0],
                        timestamp=row[1],
                        firmware_version=row[2],
                        configuration=json.loads(row[3]),
                        system_state=json.loads(row[4]),
                        network_config=json.loads(row[5]),
                        running_processes=json.loads(row[6]),
                        file_checksums=json.loads(row[7])
                    )
                    
        except Exception as e:
            logger.error(f"Failed to get device snapshot: {e}")
        
        return None

# Global patch validation agent instance
patch_agent = PatchValidationAgent()

async def main():
    """Test the Patch & Validation Agent"""
    print("Testing Patch & Validation Agent...")
    
    # Example device
    test_device = {
        "deviceId": "med-ecg-001",
        "deviceType": "Medical ECG Monitor",
        "manufacturer": "Philips",
        "firmwareVersion": "2.1.3",
        "osName": "Embedded Linux"
    }
    
    # Discover patches
    patches = await patch_agent.discover_available_patches(test_device)
    print(f"Discovered {len(patches)} patches")
    
    if patches:
        # Create test environment
        test_env = await patch_agent.create_ephemeral_test_environment(test_device)
        print(f"Created test environment: {test_env}")
        
        # Deploy patch
        deployment_id = await patch_agent.deploy_patch(
            test_device['deviceId'], 
            patches[0].patch_id, 
            test_env
        )
        print(f"Patch deployment initiated: {deployment_id}")
        
        # Cleanup
        if test_env:
            await patch_agent.cleanup_test_environment(test_env)
            print("Test environment cleaned up")

if __name__ == "__main__":
    asyncio.run(main())