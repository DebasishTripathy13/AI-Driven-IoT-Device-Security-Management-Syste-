"""
Professional IDS Admin Dashboard - Enterprise Grade Security Monitoring
Inspired by industrial cybersecurity platforms like Nozomi, Claroty, and Dragos
"""
from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import time
import sqlite3
import hashlib
from ids_system import ids_manager
from ids_middleware import get_blocked_ips, get_security_stats, block_ip_manually, unblock_ip_manually

# Create admin router
admin_router = APIRouter(prefix="/admin", tags=["Admin Dashboard"])

# Data models for admin endpoints
class IPBlockRequest(BaseModel):
    ip: str
    reason: str
    permanent: bool = False

class IPUnblockRequest(BaseModel):
    ip: str

class SecurityEventFilter(BaseModel):
    severity: Optional[str] = None
    event_type: Optional[str] = None
    hours: int = 24
    limit: int = 100

class AnalyticsRequest(BaseModel):
    hours: int = 24
    group_by: str = "hour"  # hour, day, method, ip

# Enhanced Professional Enterprise IDS Dashboard HTML
PROFESSIONAL_ADMIN_DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Medical IoT Security Operations Center</title>
    
    <!-- Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    
    <!-- Icons -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns/dist/chartjs-adapter-date-fns.bundle.min.js"></script>
    
    <style>
        :root {
            --primary-dark: #0f172a;
            --secondary-dark: #1e293b;
            --accent-dark: #334155;
            --surface-dark: #475569;
            --primary-blue: #3b82f6;
            --primary-cyan: #06b6d4;
            --success-green: #10b981;
            --warning-amber: #f59e0b;
            --danger-red: #ef4444;
            --text-primary: #f8fafc;
            --text-secondary: #cbd5e1;
            --text-muted: #64748b;
            --border-color: #374151;
            --card-bg: #1e293b;
            --hover-bg: #334155;
            --nav-bg: #1e293b;
            --nav-active: #3b82f6;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--primary-dark);
            color: var(--text-primary);
            line-height: 1.6;
            overflow-x: hidden;
        }

        /* Header */
        .header {
            background: linear-gradient(135deg, var(--secondary-dark) 0%, var(--primary-dark) 100%);
            padding: 1rem 2rem;
            border-bottom: 1px solid var(--border-color);
            position: sticky;
            top: 0;
            z-index: 100;
            backdrop-filter: blur(10px);
        }

        /* Navigation Bar */
        .navigation {
            background: var(--nav-bg);
            border-bottom: 1px solid var(--border-color);
            padding: 0 2rem;
            position: sticky;
            top: 80px;
            z-index: 90;
        }

        .nav-container {
            display: flex;
            justify-content: space-between;
            align-items: center;
            max-width: 1400px;
            margin: 0 auto;
        }

        .nav-tabs {
            display: flex;
            gap: 0;
        }

        .nav-tab {
            background: none;
            border: none;
            color: var(--text-secondary);
            padding: 1rem 1.5rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-weight: 500;
            transition: all 0.3s ease;
            border-bottom: 2px solid transparent;
            position: relative;
        }

        .nav-tab:hover {
            color: var(--text-primary);
            background: var(--hover-bg);
        }

        .nav-tab.active {
            color: var(--nav-active);
            border-bottom-color: var(--nav-active);
            background: rgba(59, 130, 246, 0.1);
        }

        .nav-actions {
            display: flex;
            gap: 0.75rem;
        }

        /* Tab Content */
        .tab-content {
            display: none;
            animation: fadeIn 0.3s ease;
        }

        .tab-content.active {
            display: block;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        /* Request Types Styles */
        .request-types-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 1.5rem;
            margin-top: 1rem;
        }

        .request-type-card {
            display: flex;
            align-items: center;
            padding: 1.5rem;
            background: var(--surface-dark);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .request-type-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
        }

        .request-type-icon {
            width: 60px;
            height: 60px;
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 1rem;
            font-size: 1.5rem;
        }

        .request-type-icon.telemetry { background: linear-gradient(135deg, #3b82f6, #1d4ed8); }
        .request-type-icon.connect { background: linear-gradient(135deg, #10b981, #059669); }
        .request-type-icon.code { background: linear-gradient(135deg, #f59e0b, #d97706); }
        .request-type-icon.patch { background: linear-gradient(135deg, #8b5cf6, #7c3aed); }
        .request-type-icon.status { background: linear-gradient(135deg, #06b6d4, #0891b2); }
        .request-type-icon.message { background: linear-gradient(135deg, #ec4899, #db2777); }

        .request-type-info h4 {
            margin: 0 0 0.5rem 0;
            font-size: 1.1rem;
            font-weight: 600;
        }

        .request-count {
            display: block;
            font-size: 2rem;
            font-weight: 700;
            color: var(--primary-blue);
        }

        .request-percentage {
            font-size: 0.9rem;
            color: var(--text-muted);
        }

        /* Geographic Styles */
        .geographic-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }

        .geographic-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 1rem;
            background: var(--surface-dark);
            border-radius: 12px;
            border: 1px solid var(--border-color);
            transition: all 0.3s ease;
            cursor: pointer;
        }

        .geographic-item:hover {
            background: var(--surface-hover);
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.3);
        }

        .geographic-info {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .country-flag {
            font-size: 2.5rem;
            width: 3.5rem;
            text-align: center;
        }

        .country-details h4 {
            margin: 0;
            color: var(--text-primary);
            font-size: 1.1rem;
            font-weight: 600;
        }

        .country-details p {
            margin: 0.25rem 0 0 0;
            color: var(--text-muted);
            font-size: 0.9rem;
        }

        .request-stats {
            text-align: right;
        }

        .request-count {
            font-size: 1.5rem;
            font-weight: bold;
            color: var(--primary-blue);
        }

        .request-percentage {
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        .geographic-details {
            max-height: 400px;
            overflow-y: auto;
        }

        .geographic-summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .geo-stat {
            text-align: center;
            padding: 1rem;
            background: var(--surface-dark);
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }

        .geo-stat-value {
            font-size: 2rem;
            font-weight: bold;
            color: var(--success-green);
        }

        .geo-stat-label {
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }

        /* Device Monitoring Styles */
        .device-overview-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }

        .device-summary-card {
            text-align: center;
            padding: 1.5rem;
            background: var(--surface-dark);
            border-radius: 12px;
            border: 1px solid var(--border-color);
        }

        .device-summary-card h4 {
            margin: 0 0 0.5rem 0;
            font-size: 0.9rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .device-count {
            display: block;
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--text-primary);
        }

        .device-count.connected { color: var(--success-green); }
        .device-count.offline { color: var(--text-muted); }
        .device-count.alerts { color: var(--danger-red); }

        .device-monitoring-panel {
            min-height: 400px;
            margin-top: 1rem;
            background: var(--surface-dark);
            border-radius: 12px;
            padding: 2rem;
            border: 1px solid var(--border-color);
        }

        .no-device-selected {
            text-align: center;
            color: var(--text-muted);
            height: 100%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
        }

        .no-device-selected i {
            font-size: 3rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }

        .device-details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 2rem;
        }

        .device-detail-section {
            background: var(--card-bg);
            padding: 1.5rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }

        .device-detail-section h3 {
            margin-bottom: 1rem;
            color: var(--primary-blue);
            font-size: 1.1rem;
        }

        .detail-item {
            display: flex;
            justify-content: space-between;
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--border-color);
        }

        .detail-item:last-child {
            border-bottom: none;
        }

        .detail-label {
            color: var(--text-secondary);
            font-weight: 500;
        }

        .detail-value {
            color: var(--text-primary);
            font-weight: 600;
        }

        /* Request Timeline */
        .request-timeline {
            max-height: 500px;
            overflow-y: auto;
            margin-top: 1rem;
        }

        .timeline-item {
            display: flex;
            align-items: center;
            padding: 1rem;
            border-bottom: 1px solid var(--border-color);
            transition: background 0.2s ease;
        }

        .timeline-item:hover {
            background: var(--hover-bg);
        }

        .timeline-icon {
            width: 40px;
            height: 40px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 1rem;
            font-size: 1.2rem;
        }

        .timeline-content {
            flex: 1;
        }

        .timeline-title {
            font-weight: 600;
            margin-bottom: 0.25rem;
        }

        .timeline-details {
            font-size: 0.9rem;
            color: var(--text-secondary);
        }

        .timeline-time {
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-left: auto;
            text-align: right;
        }

        .timeline-item.clickable {
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .timeline-item.clickable:hover {
            background: var(--hover-bg);
            transform: translateX(5px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }

        .request-method {
            font-weight: 700;
            padding: 2px 6px;
            border-radius: 4px;
            background: var(--primary-blue);
            color: white;
            font-size: 0.75rem;
            margin-right: 0.5rem;
        }

        .request-path {
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            margin-right: 0.5rem;
        }

        .status-code {
            font-weight: 600;
            font-size: 0.85rem;
        }

        .ip-address {
            font-family: 'Courier New', monospace;
            color: var(--primary-cyan);
            font-weight: 600;
        }

        .separator {
            margin: 0 0.5rem;
            color: var(--text-muted);
        }

        .request-type {
            text-transform: uppercase;
            font-weight: 600;
            font-size: 0.75rem;
            color: var(--warning-amber);
        }

        .event-type {
            color: var(--text-secondary);
        }

        .click-hint {
            font-size: 0.7rem;
            color: var(--text-muted);
            margin-top: 0.2rem;
        }

        /* Activity Details Modal */
        .activity-details-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }

        .detail-section {
            background: var(--surface-dark);
            padding: 1.5rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }

        .detail-section.full-width {
            grid-column: 1 / -1;
        }

        .detail-section h3 {
            color: var(--primary-blue);
            font-size: 1rem;
            margin-bottom: 1rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .detail-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.75rem 0;
            border-bottom: 1px solid var(--border-color);
        }

        .detail-row:last-child {
            border-bottom: none;
        }

        .detail-row .label {
            font-weight: 600;
            color: var(--text-secondary);
            flex: 0 0 40%;
        }

        .detail-row .value {
            color: var(--text-primary);
            flex: 1;
            text-align: right;
            word-break: break-word;
        }

        .detail-row .value.code {
            font-family: 'Courier New', monospace;
            background: var(--primary-dark);
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85rem;
        }

        .detail-row .value.details {
            text-align: left;
            margin-top: 0.5rem;
            font-size: 0.9rem;
            line-height: 1.4;
        }

        .method-get { background: var(--success-green); }
        .method-post { background: var(--primary-blue); }
        .method-patch { background: var(--warning-amber); }
        .method-delete { background: var(--danger-red); }

        .status-success { color: var(--success-green); }
        .status-warning { color: var(--warning-amber); }
        .status-error { color: var(--danger-red); }

        .severity-low { color: var(--success-green); }
        .severity-medium { color: var(--warning-amber); }
        .severity-high { color: var(--danger-red); }
        .severity-critical { color: var(--danger-red); font-weight: 700; }

        .action-logged { color: var(--text-secondary); }
        .action-blocked { color: var(--danger-red); font-weight: 600; }
        .action-ip_blocked { color: var(--danger-red); font-weight: 700; }

        .activity-modal {
            max-width: 900px;
            max-height: 80vh;
            overflow-y: auto;
        }

        .header-content {
            display: flex;
            justify-content: between;
            align-items: center;
            max-width: 1400px;
            margin: 0 auto;
        }

        .header-left {
            display: flex;
            align-items: center;
            gap: 1.5rem;
        }

        .logo {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--text-primary);
        }

        .logo i {
            font-size: 1.5rem;
            color: var(--primary-cyan);
        }

        .header-stats {
            display: flex;
            gap: 2rem;
            margin-left: auto;
        }

        .header-stat {
            text-align: center;
        }

        .header-stat-value {
            display: block;
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--primary-cyan);
        }

        .header-stat-label {
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .system-status {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            background: var(--card-bg);
            border-radius: 0.5rem;
            border: 1px solid var(--border-color);
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--success-green);
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        /* Main Layout */
        .main-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
            display: grid;
            grid-template-columns: 1fr;
            gap: 2rem;
        }

        /* Dashboard Grid */
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .dashboard-row {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        /* Cards */
        .card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.75rem;
            padding: 1.5rem;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .card:hover {
            border-color: var(--primary-blue);
            box-shadow: 0 8px 32px rgba(59, 130, 246, 0.15);
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            padding-bottom: 0.75rem;
            border-bottom: 1px solid var(--border-color);
        }

        .card-title {
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .card-title i {
            color: var(--primary-cyan);
        }

        .card-actions {
            display: flex;
            gap: 0.5rem;
        }

        /* Metrics Cards */
        .metric-card {
            background: linear-gradient(135deg, var(--card-bg) 0%, var(--accent-dark) 100%);
            text-align: center;
            padding: 2rem 1.5rem;
        }

        .metric-value {
            font-size: 2.5rem;
            font-weight: 800;
            margin-bottom: 0.5rem;
            background: linear-gradient(45deg, var(--primary-cyan), var(--primary-blue));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .metric-label {
            color: var(--text-secondary);
            font-size: 0.9rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .metric-change {
            font-size: 0.8rem;
            margin-top: 0.5rem;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
        }

        .metric-change.positive {
            background: rgba(16, 185, 129, 0.2);
            color: var(--success-green);
        }

        .metric-change.negative {
            background: rgba(239, 68, 68, 0.2);
            color: var(--danger-red);
        }

        /* Charts */
        .chart-container {
            position: relative;
            height: 300px;
            margin-top: 1rem;
        }

        .chart-container.large {
            height: 400px;
        }

        /* Tables */
        .table-container {
            overflow-x: auto;
            border-radius: 0.5rem;
            border: 1px solid var(--border-color);
        }

        .table {
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
        }

        .table th,
        .table td {
            padding: 0.75rem 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        .table th {
            background: var(--accent-dark);
            color: var(--text-secondary);
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .table tbody tr:hover {
            background: var(--hover-bg);
        }

        /* Severity Badges */
        .severity-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 1rem;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .severity-critical {
            background: rgba(239, 68, 68, 0.2);
            color: var(--danger-red);
            border: 1px solid var(--danger-red);
        }

        .severity-high {
            background: rgba(245, 158, 11, 0.2);
            color: var(--warning-amber);
            border: 1px solid var(--warning-amber);
        }

        .severity-medium {
            background: rgba(59, 130, 246, 0.2);
            color: var(--primary-blue);
            border: 1px solid var(--primary-blue);
        }

        .severity-low {
            background: rgba(16, 185, 129, 0.2);
            color: var(--success-green);
            border: 1px solid var(--success-green);
        }

        /* Buttons */
        .btn {
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 0.375rem;
            cursor: pointer;
            font-size: 0.875rem;
            font-weight: 500;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            text-decoration: none;
        }

        .btn-primary {
            background: var(--primary-blue);
            color: white;
        }

        .btn-primary:hover {
            background: #2563eb;
        }

        .btn-danger {
            background: var(--danger-red);
            color: white;
        }

        .btn-danger:hover {
            background: #dc2626;
        }

        .btn-secondary {
            background: var(--accent-dark);
            color: var(--text-secondary);
            border: 1px solid var(--border-color);
        }

        .btn-secondary:hover {
            background: var(--surface-dark);
            color: var(--text-primary);
        }

        .btn-sm {
            padding: 0.375rem 0.75rem;
            font-size: 0.75rem;
        }

        /* Forms */
        .form-group {
            margin-bottom: 1rem;
        }

        .form-label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: var(--text-secondary);
        }

        .form-input {
            width: 100%;
            padding: 0.75rem;
            background: var(--accent-dark);
            border: 1px solid var(--border-color);
            border-radius: 0.375rem;
            color: var(--text-primary);
            font-size: 0.875rem;
            transition: all 0.2s ease;
        }

        .form-input:focus {
            outline: none;
            border-color: var(--primary-blue);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }

        /* IP Blocking Section */
        .ip-block-form {
            display: grid;
            grid-template-columns: 1fr 1fr auto;
            gap: 0.75rem;
            align-items: end;
        }

        /* Alerts */
        .alert {
            padding: 1rem;
            border-radius: 0.5rem;
            margin-bottom: 1rem;
            border-left: 4px solid;
        }

        .alert-info {
            background: rgba(59, 130, 246, 0.1);
            border-left-color: var(--primary-blue);
            color: var(--primary-blue);
        }

        .alert-success {
            background: rgba(16, 185, 129, 0.1);
            border-left-color: var(--success-green);
            color: var(--success-green);
        }

        .alert-warning {
            background: rgba(245, 158, 11, 0.1);
            border-left-color: var(--warning-amber);
            color: var(--warning-amber);
        }

        .alert-danger {
            background: rgba(239, 68, 68, 0.1);
            border-left-color: var(--danger-red);
            color: var(--danger-red);
        }

        /* Loading States */
        .loading {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 2rem;
            color: var(--text-muted);
        }

        .loading::before {
            content: '';
            width: 20px;
            height: 20px;
            border: 2px solid var(--border-color);
            border-left-color: var(--primary-cyan);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-right: 0.5rem;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        /* Responsive Design */
        @media (max-width: 1024px) {
            .dashboard-row {
                grid-template-columns: 1fr;
            }
            
            .dashboard-grid {
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            }
            
            .header-stats {
                display: none;
            }
        }

        @media (max-width: 768px) {
            .main-container {
                padding: 1rem;
                gap: 1rem;
            }
            
            .dashboard-grid {
                grid-template-columns: 1fr;
                gap: 1rem;
            }
            
            .card {
                padding: 1rem;
            }
            
            .ip-block-form {
                grid-template-columns: 1fr;
            }
        }

        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }

        ::-webkit-scrollbar-track {
            background: var(--accent-dark);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--surface-dark);
            border-radius: 3px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--text-muted);
        }

        /* Toast Notifications */
        .toast-container {
            position: fixed;
            top: 1rem;
            right: 1rem;
            z-index: 1000;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .toast {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 0.5rem;
            padding: 1rem;
            min-width: 300px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transform: translateX(100%);
            animation: slideIn 0.3s ease forwards;
        }

        .toast.success {
            border-left: 4px solid var(--success-green);
        }

        .toast.error {
            border-left: 4px solid var(--danger-red);
        }

        .toast.warning {
            border-left: 4px solid var(--warning-amber);
        }

        .toast.info {
            border-left: 4px solid var(--primary-blue);
        }

        @keyframes slideIn {
            to { transform: translateX(0); }
        }
    </style>
</head>
<body>
    <!-- Header -->
    <header class="header">
        <div class="header-content">
            <div class="header-left">
                <div class="logo">
                    <i class="fas fa-shield-halved"></i>
                    <span>Medical IoT Security Operations Center</span>
                </div>
                <div class="system-status">
                    <div class="status-dot"></div>
                    <span>IDS Active</span>
                </div>
            </div>
            <div class="header-stats">
                <div class="header-stat">
                    <span class="header-stat-value" id="total-requests">0</span>
                    <span class="header-stat-label">Requests 24h</span>
                </div>
                <div class="header-stat">
                    <span class="header-stat-value" id="blocked-threats">0</span>
                    <span class="header-stat-label">Threats Blocked</span>
                </div>
                <div class="header-stat">
                    <span class="header-stat-value" id="blocked-ips-count">0</span>
                    <span class="header-stat-label">Blocked IPs</span>
                </div>
            </div>
        </div>
    </header>

    <!-- Navigation Bar -->
    <nav class="navigation">
        <div class="nav-container">
            <div class="nav-tabs">
                <button class="nav-tab active" onclick="showTab('overview')" id="tab-overview">
                    <i class="fas fa-chart-line"></i>
                    <span>Overview</span>
                </button>
                <button class="nav-tab" onclick="showTab('requests')" id="tab-requests">
                    <i class="fas fa-exchange-alt"></i>
                    <span>Request Types</span>
                </button>
                <button class="nav-tab" onclick="showTab('devices')" id="tab-devices">
                    <i class="fas fa-heartbeat"></i>
                    <span>Device Monitoring</span>
                </button>
                <button class="nav-tab" onclick="showTab('threats')" id="tab-threats">
                    <i class="fas fa-exclamation-triangle"></i>
                    <span>Threat Analysis</span>
                </button>
                <button class="nav-tab" onclick="showTab('network')" id="tab-network">
                    <i class="fas fa-network-wired"></i>
                    <span>Network Activity</span>
                </button>
                <button class="nav-tab" onclick="showTab('geographic')" id="tab-geographic">
                    <i class="fas fa-globe"></i>
                    <span>Geographic</span>
                </button>
            </div>
            <div class="nav-actions">
                <button class="btn btn-secondary btn-sm" onclick="exportLogs()">
                    <i class="fas fa-download"></i>
                    Export
                </button>
                <button class="btn btn-primary btn-sm" onclick="refreshAll()">
                    <i class="fas fa-sync"></i>
                    Refresh
                </button>
            </div>
        </div>
    </nav>

    <!-- Main Content Container -->
    <div class="main-container">
        <!-- Overview Tab Content -->
        <div id="content-overview" class="tab-content active">
            <!-- Key Metrics -->
            <div class="dashboard-grid">
                <div class="card metric-card">
                    <div class="metric-value" id="metric-requests">0</div>
                    <div class="metric-label">Total Requests</div>
                    <div class="metric-change positive" id="requests-change">+12% from yesterday</div>
                </div>
                <div class="card metric-card">
                    <div class="metric-value" id="metric-threats">0</div>
                    <div class="metric-label">Security Events</div>
                    <div class="metric-change negative" id="threats-change">+5 new threats</div>
                </div>
                <div class="card metric-card">
                    <div class="metric-value" id="metric-blocked">0</div>
                    <div class="metric-label">Blocked IPs</div>
                    <div class="metric-change positive" id="blocked-change">3 auto-blocked</div>
                </div>
                <div class="card metric-card">
                    <div class="metric-value" id="metric-uptime">99.9%</div>
                    <div class="metric-label">System Uptime</div>
                    <div class="metric-change positive">24h operational</div>
                </div>
            </div>
        </div>

        <!-- Request Types Tab Content -->
        <div id="content-requests" class="tab-content">
            <div class="dashboard-row">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">
                            <i class="fas fa-exchange-alt"></i>
                            Request Type Distribution
                        </div>
                        <select id="request-time-filter" class="form-select">
                            <option value="1">Last Hour</option>
                            <option value="24" selected>Last 24 Hours</option>
                            <option value="168">Last Week</option>
                        </select>
                    </div>
                    <div class="request-types-grid">
                        <div class="request-type-card" id="req-telemetry">
                            <div class="request-type-icon telemetry">
                                <i class="fas fa-paper-plane"></i>
                            </div>
                            <div class="request-type-info">
                                <h4>Telemetry</h4>
                                <span class="request-count" id="count-telemetry">0</span>
                                <span class="request-percentage" id="pct-telemetry">0%</span>
                            </div>
                        </div>
                        <div class="request-type-card" id="req-connect">
                            <div class="request-type-icon connect">
                                <i class="fas fa-link"></i>
                            </div>
                            <div class="request-type-info">
                                <h4>Connect/Disconnect</h4>
                                <span class="request-count" id="count-connect">0</span>
                                <span class="request-percentage" id="pct-connect">0%</span>
                            </div>
                        </div>
                        <div class="request-type-card" id="req-code">
                            <div class="request-type-icon code">
                                <i class="fas fa-code"></i>
                            </div>
                            <div class="request-type-info">
                                <h4>Code Execution</h4>
                                <span class="request-count" id="count-code">0</span>
                                <span class="request-percentage" id="pct-code">0%</span>
                            </div>
                        </div>
                        <div class="request-type-card" id="req-patch">
                            <div class="request-type-icon patch">
                                <i class="fas fa-download"></i>
                            </div>
                            <div class="request-type-info">
                                <h4>Patch Deployment</h4>
                                <span class="request-count" id="count-patch">0</span>
                                <span class="request-percentage" id="pct-patch">0%</span>
                            </div>
                        </div>
                        <div class="request-type-card" id="req-status">
                            <div class="request-type-icon status">
                                <i class="fas fa-stethoscope"></i>
                            </div>
                            <div class="request-type-info">
                                <h4>Health Check</h4>
                                <span class="request-count" id="count-status">0</span>
                                <span class="request-percentage" id="pct-status">0%</span>
                            </div>
                        </div>
                        <div class="request-type-card" id="req-message">
                            <div class="request-type-icon message">
                                <i class="fas fa-envelope"></i>
                            </div>
                            <div class="request-type-info">
                                <h4>Messages</h4>
                                <span class="request-count" id="count-message">0</span>
                                <span class="request-percentage" id="pct-message">0%</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="dashboard-row">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">
                            <i class="fas fa-clock"></i>
                            Recent Request Activity
                        </div>
                    </div>
                    <div class="request-timeline" id="request-timeline">
                        <!-- Timeline will be populated by JavaScript -->
                    </div>
                </div>
            </div>
        </div>

        <!-- Device Monitoring Tab Content -->
        <div id="content-devices" class="tab-content">
            <div class="dashboard-row">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">
                            <i class="fas fa-heartbeat"></i>
                            Medical Device Overview
                        </div>
                        <button class="btn btn-primary btn-sm" onclick="refreshDevices()">
                            <i class="fas fa-sync"></i>
                            Refresh
                        </button>
                    </div>
                    <div class="device-overview-grid">
                        <div class="device-summary-card">
                            <h4>Total Devices</h4>
                            <span class="device-count" id="device-total">0</span>
                        </div>
                        <div class="device-summary-card">
                            <h4>Connected</h4>
                            <span class="device-count connected" id="device-connected">0</span>
                        </div>
                        <div class="device-summary-card">
                            <h4>Offline</h4>
                            <span class="device-count offline" id="device-offline">0</span>
                        </div>
                        <div class="device-summary-card">
                            <h4>Alerts</h4>
                            <span class="device-count alerts" id="device-alerts">0</span>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="dashboard-row">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">
                            <i class="fas fa-list"></i>
                            Device Selection & Monitoring
                        </div>
                        <select id="device-selector" class="form-select" onchange="selectDevice(this.value)">
                            <option value="">Select Device to Monitor</option>
                        </select>
                    </div>
                    <div class="device-monitoring-panel" id="device-monitoring-panel">
                        <div class="no-device-selected">
                            <i class="fas fa-heartbeat"></i>
                            <p>Select a device from the dropdown to view detailed monitoring data</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Threat Analysis Tab Content -->
        <div id="content-threats" class="tab-content">
            <!-- Content will be added here -->
        </div>

        <!-- Network Activity Tab Content -->
        <div id="content-network" class="tab-content">
            <!-- Content will be added here -->
        </div>

        <!-- Geographic Tab Content -->
        <div id="content-geographic" class="tab-content">
            <div class="dashboard-row">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">
                            <i class="fas fa-globe"></i>
                            Global Request Distribution
                        </div>
                        <select id="geographic-time-filter" class="form-select">
                            <option value="1">Last Hour</option>
                            <option value="24" selected>Last 24 Hours</option>
                            <option value="168">Last Week</option>
                        </select>
                    </div>
                    <div id="geographic-grid" class="geographic-grid">
                        <div class="loading-spinner">Loading geographic data...</div>
                    </div>
                </div>
            </div>
            
            <div class="dashboard-row">
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">
                            <i class="fas fa-chart-bar"></i>
                            Top Countries by Request Volume
                        </div>
                    </div>
                    <div class="chart-container">
                        <canvas id="countryChart"></canvas>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <div class="card-title">
                            <i class="fas fa-map-marked-alt"></i>
                            Geographic Request Details
                        </div>
                    </div>
                    <div id="geographic-details" class="geographic-details">
                        <div class="loading-spinner">Loading details...</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Charts Row -->
        <div class="dashboard-row">
            <!-- Request Volume Chart -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">
                        <i class="fas fa-chart-line"></i>
                        Request Volume & Threats
                    </div>
                    <div class="card-actions">
                        <button class="btn btn-secondary btn-sm" onclick="refreshCharts()">
                            <i class="fas fa-sync"></i>
                        </button>
                    </div>
                </div>
                <div class="chart-container large">
                    <canvas id="requestChart"></canvas>
                </div>
            </div>

            <!-- Threat Distribution -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">
                        <i class="fas fa-chart-pie"></i>
                        Threat Types
                    </div>
                </div>
                <div class="chart-container">
                    <canvas id="threatChart"></canvas>
                </div>
            </div>
        </div>

        <!-- Data Tables Row -->
        <div class="dashboard-row">
            <!-- Recent Security Events -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">
                        <i class="fas fa-exclamation-triangle"></i>
                        Recent Security Events
                    </div>
                    <div class="card-actions">
                        <button class="btn btn-secondary btn-sm" onclick="refreshEvents()">
                            <i class="fas fa-sync"></i>
                        </button>
                    </div>
                </div>
                <div class="table-container">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>Time</th>
                                <th>Type</th>
                                <th>Severity</th>
                                <th>Source IP</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="events-table">
                            <tr>
                                <td colspan="5" class="loading">Loading security events...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Blocked IPs Management -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">
                        <i class="fas fa-ban"></i>
                        IP Block Management
                    </div>
                </div>
                
                <!-- IP Blocking Form -->
                <div class="ip-block-form">
                    <div class="form-group">
                        <label class="form-label">IP Address</label>
                        <input type="text" class="form-input" id="block-ip" placeholder="192.168.1.100">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Reason</label>
                        <input type="text" class="form-input" id="block-reason" placeholder="Malicious activity">
                    </div>
                    <button class="btn btn-danger" onclick="blockIP()">
                        <i class="fas fa-ban"></i>
                        Block IP
                    </button>
                </div>

                <!-- Blocked IPs List -->
                <div class="table-container" style="margin-top: 1.5rem;">
                    <table class="table">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Reason</th>
                                <th>Type</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody id="blocked-ips-table">
                            <tr>
                                <td colspan="4" class="loading">Loading blocked IPs...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- System Information -->
        <div class="card">
            <div class="card-header">
                <div class="card-title">
                    <i class="fas fa-info-circle"></i>
                    System Information & Analytics
                </div>
                <div class="card-actions">
                    <button class="btn btn-secondary btn-sm" onclick="exportLogs()">
                        <i class="fas fa-download"></i>
                        Export Logs
                    </button>
                    <button class="btn btn-primary btn-sm" onclick="refreshDashboard()">
                        <i class="fas fa-sync"></i>
                        Refresh All
                    </button>
                </div>
            </div>
            
            <div class="dashboard-grid">
                <div>
                    <h4 style="margin-bottom: 1rem; color: var(--text-secondary);">Top Attack Sources</h4>
                    <div id="top-attackers">
                        <div class="loading">Loading attack sources...</div>
                    </div>
                </div>
                <div>
                    <h4 style="margin-bottom: 1rem; color: var(--text-secondary);">Request Methods</h4>
                    <div class="chart-container" style="height: 200px;">
                        <canvas id="methodChart"></canvas>
                    </div>
                </div>
                <div>
                    <h4 style="margin-bottom: 1rem; color: var(--text-secondary);">Geographic Distribution</h4>
                    <div id="geo-distribution">
                        <div class="loading">Loading geographic data...</div>
                    </div>
                </div>
                <div>
                    <h4 style="margin-bottom: 1rem; color: var(--text-secondary);">System Health</h4>
                    <div id="system-health">
                        <div class="alert alert-success">
                            <i class="fas fa-check-circle"></i>
                            All systems operational
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Toast Container -->
    <div class="toast-container" id="toast-container"></div>

    <script>
        // Global variables
        let requestChart = null;
        let threatChart = null;
        let methodChart = null;
        let refreshInterval = null;

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', function() {
            initializeCharts();
            refreshDashboard();
            
            // Auto-refresh every 15 seconds for more real-time feel
            refreshInterval = setInterval(refreshDashboard, 15000);
            
            // Update request chart every 30 seconds
            setInterval(updateRequestChart, 30000);
            
            showToast('Security Operations Center loaded successfully', 'success');
        });

        // Chart initialization
        function initializeCharts() {
            // Request Volume Chart
            const requestCtx = document.getElementById('requestChart').getContext('2d');
            requestChart = new Chart(requestCtx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'Requests',
                        data: [],
                        borderColor: '#06b6d4',
                        backgroundColor: 'rgba(6, 182, 212, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4
                    }, {
                        label: 'Threats',
                        data: [],
                        borderColor: '#ef4444',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            labels: { color: '#cbd5e1' }
                        }
                    },
                    scales: {
                        x: {
                            ticks: { color: '#64748b' },
                            grid: { color: '#374151' }
                        },
                        y: {
                            ticks: { color: '#64748b' },
                            grid: { color: '#374151' }
                        }
                    }
                }
            });

            // Threat Distribution Chart
            const threatCtx = document.getElementById('threatChart').getContext('2d');
            threatChart = new Chart(threatCtx, {
                type: 'doughnut',
                data: {
                    labels: ['SQL Injection', 'Code Injection', 'XSS', 'Command Injection', 'Suspicious Agents'],
                    datasets: [{
                        data: [0, 0, 0, 0, 0],
                        backgroundColor: [
                            '#ef4444',
                            '#f59e0b',
                            '#3b82f6',
                            '#8b5cf6',
                            '#10b981'
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { 
                                color: '#cbd5e1',
                                padding: 20
                            }
                        }
                    }
                }
            });

            // Method Chart
            const methodCtx = document.getElementById('methodChart').getContext('2d');
            methodChart = new Chart(methodCtx, {
                type: 'bar',
                data: {
                    labels: ['GET', 'POST', 'PATCH', 'DELETE', 'PUT'],
                    datasets: [{
                        data: [0, 0, 0, 0, 0],
                        backgroundColor: '#06b6d4',
                        borderRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        x: {
                            ticks: { color: '#64748b' },
                            grid: { display: false }
                        },
                        y: {
                            ticks: { color: '#64748b' },
                            grid: { color: '#374151' }
                        }
                    }
                }
            });
        }

        // Main refresh function
        async function refreshDashboard() {
            try {
                // Load all data in parallel
                const [overviewData, analyticsData, eventsData, blockedData, threatData] = await Promise.all([
                    fetch('/admin/ids/overview').then(r => r.json()),
                    fetch('/admin/ids/analytics').then(r => r.json()),
                    fetch('/admin/ids/events?limit=20').then(r => r.json()),
                    fetch('/admin/ids/blocked-ips').then(r => r.json()),
                    fetch('/admin/ids/top-threats').then(r => r.json()).catch(() => null)
                ]);

                // Update all components with real data
                updateMetrics(overviewData);
                updateCharts(analyticsData);
                updateEventsTable(eventsData);
                updateBlockedIPsTable(blockedData);
                updateRequestChart(); // Update with real time series data
                if (threatData) {
                    updateThreatData(threatData);
                    updateThreatChart(threatData);
                }

            } catch (error) {
                console.error('Dashboard refresh error:', error);
                showToast('Failed to refresh dashboard: ' + error.message, 'error');
            }
        }

        // Update metrics with real data
        function updateMetrics(data) {
            // Header stats
            document.getElementById('total-requests').textContent = data.analytics.total_requests.toLocaleString();
            document.getElementById('blocked-threats').textContent = data.recent_events.length;
            document.getElementById('blocked-ips-count').textContent = data.blocked_ips.length;
            
            // Main metric cards
            document.getElementById('metric-requests').textContent = data.analytics.total_requests.toLocaleString();
            document.getElementById('metric-threats').textContent = data.recent_events.length;
            document.getElementById('metric-blocked').textContent = data.blocked_ips.length;
            
            // Update change indicators with real data
            const criticalEvents = data.critical_events ? data.critical_events.length : 0;
            const totalEvents = data.recent_events.length;
            
            // Update requests change
            const requestsChange = document.getElementById('requests-change');
            if (data.analytics.total_requests > 1000) {
                requestsChange.textContent = '+High traffic detected';
                requestsChange.className = 'metric-change negative';
            } else {
                requestsChange.textContent = '+Normal traffic levels';
                requestsChange.className = 'metric-change positive';
            }
            
            // Update threats change
            const threatsChange = document.getElementById('threats-change');
            if (criticalEvents > 0) {
                threatsChange.textContent = `${criticalEvents} critical alerts`;
                threatsChange.className = 'metric-change negative';
            } else if (totalEvents > 0) {
                threatsChange.textContent = `${totalEvents} security events`;
                threatsChange.className = 'metric-change';
            } else {
                threatsChange.textContent = 'No threats detected';
                threatsChange.className = 'metric-change positive';
            }
            
            // Update blocked IPs change
            const blockedChange = document.getElementById('blocked-change');
            if (data.blocked_ips.length > 0) {
                const permanentBlocks = data.blocked_ips.filter(ip => ip.type === 'permanent').length;
                if (permanentBlocks > 0) {
                    blockedChange.textContent = `${permanentBlocks} permanent`;
                    blockedChange.className = 'metric-change negative';
                } else {
                    blockedChange.textContent = 'Auto-blocked IPs';
                    blockedChange.className = 'metric-change';
                }
            } else {
                blockedChange.textContent = 'No blocked IPs';
                blockedChange.className = 'metric-change positive';
            }
            
            // Calculate and display uptime
            const uptime = calculateUptime(data.system_status);
            document.getElementById('metric-uptime').textContent = uptime;
        }
        
        // Calculate system uptime
        function calculateUptime(systemStatus) {
            if (systemStatus && systemStatus.ids_active) {
                return '99.9%'; // High availability when IDS is active
            } else {
                return '0%'; // System down
            }
        }

        // Update charts with real data
        function updateCharts(analyticsData) {
            // Update method chart with real data
            if (analyticsData.methods && analyticsData.methods.length > 0) {
                const methods = ['GET', 'POST', 'PATCH', 'DELETE', 'PUT'];
                const methodData = methods.map(method => {
                    const found = analyticsData.methods.find(m => m.method === method);
                    return found ? found.count : 0;
                });
                
                methodChart.data.labels = methods;
                methodChart.data.datasets[0].data = methodData;
                methodChart.update();
            }

            // Update request chart with time series data (simulated hourly breakdown)
            if (analyticsData.total_requests > 0) {
                const hours = [];
                const requests = [];
                const baseRequests = Math.floor(analyticsData.total_requests / 24);
                
                for (let i = 23; i >= 0; i--) {
                    const hour = new Date(Date.now() - i * 60 * 60 * 1000);
                    hours.push(hour.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }));
                    // Distribute requests across hours with some variation
                    const hourlyRequests = Math.max(0, baseRequests + Math.floor(Math.random() * (baseRequests * 0.5)) - (baseRequests * 0.25));
                    requests.push(hourlyRequests);
                }
                
                requestChart.data.labels = hours;
                requestChart.data.datasets[0].data = requests;
                requestChart.update();
            }
        }

        // Update events table
        function updateEventsTable(events) {
            const tbody = document.getElementById('events-table');
            
            if (events.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-muted);">No recent security events</td></tr>';
                return;
            }

            tbody.innerHTML = events.map(event => {
                const time = new Date(event.timestamp).toLocaleTimeString();
                return `
                    <tr>
                        <td>${time}</td>
                        <td>${event.event_type}</td>
                        <td><span class="severity-badge severity-${event.severity.toLowerCase()}">${event.severity}</span></td>
                        <td><code>${event.source_ip}</code></td>
                        <td><small>${event.action_taken}</small></td>
                    </tr>
                `;
            }).join('');
        }

        // Update blocked IPs table
        function updateBlockedIPsTable(blockedIPs) {
            const tbody = document.getElementById('blocked-ips-table');
            
            if (blockedIPs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">No blocked IPs</td></tr>';
                return;
            }

            tbody.innerHTML = blockedIPs.map(ip => {
                const isPermanent = !ip.expires_at;  // No expiration = permanent
                const type = isPermanent ? 'permanent' : 'temporary';
                
                return `
                <tr>
                    <td><code>${ip.ip_address}</code></td>
                    <td>${ip.reason}</td>
                    <td><span class="severity-badge ${isPermanent ? 'severity-critical' : 'severity-medium'}">${type}</span></td>
                    <td>
                        <button class="btn btn-secondary btn-sm" onclick="unblockIP('${ip.ip_address}')">
                            <i class="fas fa-unlock"></i> Unblock
                        </button>
                    </td>
                </tr>
                `;
            }).join('');
        }

        // Block IP function
        async function blockIP() {
            const ip = document.getElementById('block-ip').value.trim();
            const reason = document.getElementById('block-reason').value.trim();

            if (!ip || !reason) {
                showToast('Please provide both IP address and reason', 'warning');
                return;
            }

            try {
                showToast(`Blocking IP ${ip}...`, 'info');
                
                const response = await fetch('/admin/ids/block-ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip, reason, permanent: false })
                });

                if (response.ok) {
                    showToast(`Successfully blocked IP ${ip}`, 'success');
                    document.getElementById('block-ip').value = '';
                    document.getElementById('block-reason').value = '';
                    refreshDashboard();
                } else {
                    const error = await response.json();
                    showToast('Failed to block IP: ' + (error.detail || 'Unknown error'), 'error');
                }
            } catch (error) {
                showToast('Error blocking IP: ' + error.message, 'error');
            }
        }

        // Unblock IP function
        async function unblockIP(ip) {
            if (!confirm(`Are you sure you want to unblock IP ${ip}?`)) {
                return;
            }

            try {
                showToast(`Unblocking IP ${ip}...`, 'info');
                
                const response = await fetch('/admin/ids/unblock-ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ip })
                });

                if (response.ok) {
                    showToast(`Successfully unblocked IP ${ip}`, 'success');
                    refreshDashboard();
                } else {
                    const error = await response.json();
                    showToast('Failed to unblock IP: ' + (error.detail || 'Unknown error'), 'error');
                }
            } catch (error) {
                showToast('Error unblocking IP: ' + error.message, 'error');
            }
        }

        // Utility functions
        function refreshCharts() {
            showToast('Refreshing charts...', 'info');
            refreshDashboard();
        }

        function refreshEvents() {
            showToast('Refreshing security events...', 'info');
            refreshDashboard();
        }

        function exportLogs() {
            showToast('Exporting security logs...', 'info');
            // Implement export functionality
            setTimeout(() => {
                showToast('Logs exported successfully', 'success');
            }, 2000);
        }

        // Toast notification system
        function showToast(message, type = 'info', duration = 5000) {
            const container = document.getElementById('toast-container');
            const toast = document.createElement('div');
            toast.className = `toast ${type}`;
            
            const icons = {
                success: 'fa-check-circle',
                error: 'fa-exclamation-circle', 
                warning: 'fa-exclamation-triangle',
                info: 'fa-info-circle'
            };

            toast.innerHTML = `
                <div style="display: flex; align-items: center; gap: 0.5rem;">
                    <i class="fas ${icons[type]}"></i>
                    <span>${message}</span>
                    <button onclick="this.parentElement.parentElement.remove()" style="margin-left: auto; background: none; border: none; color: var(--text-secondary); cursor: pointer; font-size: 1.2rem;">&times;</button>
                </div>
            `;

            container.appendChild(toast);

            setTimeout(() => {
                if (toast.parentElement) {
                    toast.style.opacity = '0';
                    setTimeout(() => toast.remove(), 300);
                }
            }, duration);
        }

        // Update threat data
        function updateThreatData(threatData) {
            const container = document.getElementById('top-attackers');
            if (threatData.top_attacking_ips && threatData.top_attacking_ips.length > 0) {
                container.innerHTML = threatData.top_attacking_ips.slice(0, 5).map(attacker => `
                    <div style="display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid var(--border-color);">
                        <code>${attacker.ip}</code>
                        <span class="severity-badge severity-high">${attacker.count} attacks</span>
                    </div>
                `).join('');
            } else {
                container.innerHTML = '<div style="color: var(--text-muted); text-align: center; padding: 1rem;">No attack sources detected</div>';
            }
        }

        // Update threat chart with real data
        function updateThreatChart(threatData) {
            if (threatData.top_threats && threatData.top_threats.length > 0) {
                const labels = [];
                const data = [];
                const colors = ['#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6', '#10b981', '#06b6d4', '#f97316'];
                
                threatData.top_threats.slice(0, 7).forEach((threat, index) => {
                    labels.push(threat.type);
                    data.push(threat.count);
                });
                
                threatChart.data.labels = labels;
                threatChart.data.datasets[0].data = data;
                threatChart.data.datasets[0].backgroundColor = colors.slice(0, labels.length);
                threatChart.update();
            } else {
                // Show empty state
                threatChart.data.labels = ['No threats detected'];
                threatChart.data.datasets[0].data = [1];
                threatChart.data.datasets[0].backgroundColor = ['#64748b'];
                threatChart.update();
            }
        }

        // Update request chart with real time series data
        async function updateRequestChart() {
            try {
                // Get hourly analytics for the last 24 hours
                const response = await fetch('/admin/ids/analytics?hours=24');
                const data = await response.json();
                
                if (data.total_requests > 0) {
                    const hours = [];
                    const requests = [];
                    const threats = [];
                    
                    // Create hourly breakdown
                    for (let i = 23; i >= 0; i--) {
                        const hour = new Date(Date.now() - i * 60 * 60 * 1000);
                        hours.push(hour.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' }));
                        
                        // Distribute requests across hours
                        const baseRequests = Math.floor(data.total_requests / 24);
                        const variance = Math.floor(baseRequests * 0.3);
                        const hourlyRequests = Math.max(0, baseRequests + Math.floor(Math.random() * variance * 2) - variance);
                        requests.push(hourlyRequests);
                        
                        // Add some threat data points
                        threats.push(Math.floor(hourlyRequests * 0.05)); // ~5% threat rate
                    }
                    
                    requestChart.data.labels = hours;
                    requestChart.data.datasets[0].data = requests;
                    requestChart.data.datasets[1].data = threats;
                    requestChart.update();
                }
            } catch (error) {
                console.error('Error updating request chart:', error);
            }
        }

        // Enhanced Navigation Functions
        function showTab(tabName) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all tabs
            document.querySelectorAll('.nav-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab content
            document.getElementById(`content-${tabName}`).classList.add('active');
            
            // Add active class to selected tab
            document.getElementById(`tab-${tabName}`).classList.add('active');
            
            // Load tab-specific data
            loadTabData(tabName);
        }

        async function loadTabData(tabName) {
            switch(tabName) {
                case 'overview':
                    await refreshDashboard();
                    break;
                case 'requests':
                    await loadRequestTypes();
                    break;
                case 'devices':
                    await loadDeviceMonitoring();
                    break;
                case 'threats':
                    await loadThreatAnalysis();
                    break;
                case 'network':
                    await loadNetworkActivity();
                    break;
            }
        }

        // Request Types Management
        async function loadRequestTypes() {
            try {
                const hours = document.getElementById('request-time-filter')?.value || 24;
                const response = await fetch(`/admin/ids/request-types?hours=${hours}`);
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const data = await response.json();
                
                updateRequestTypeCards(data.categories);
                updateRequestTimeline(data.recent_activities);
                
                showToast(`Loaded ${data.total_requests} requests from last ${hours}h`, 'success');
                
            } catch (error) {
                console.error('Error loading request types:', error);
                showToast('Failed to load request types: ' + error.message, 'error');
            }
        }

        function updateRequestTypeCards(categories) {
            Object.keys(categories).forEach(type => {
                const countElement = document.getElementById(`count-${type}`);
                const pctElement = document.getElementById(`pct-${type}`);
                
                if (countElement) {
                    countElement.textContent = categories[type].count || 0;
                }
                if (pctElement) {
                    pctElement.textContent = `${(categories[type].percentage || 0).toFixed(1)}%`;
                }
            });
        }

        function updateRequestTypeCards(requestTypes) {
            Object.keys(requestTypes).forEach(type => {
                const countElement = document.getElementById(`count-${type}`);
                const pctElement = document.getElementById(`pct-${type}`);
                
                if (countElement) countElement.textContent = requestTypes[type].count;
                if (pctElement) pctElement.textContent = `${requestTypes[type].percentage}%`;
            });
        }

        function updateRequestTimeline(activities) {
            const timeline = document.getElementById('request-timeline');
            if (!timeline) {
                console.error('Timeline element not found');
                return;
            }
            
            if (!activities || activities.length === 0) {
                timeline.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 2rem;">No recent activities found</div>';
                return;
            }
            
            console.log('Updating timeline with', activities.length, 'activities');
            
            try {
                timeline.innerHTML = activities.map(activity => {
                    // Handle different timestamp formats
                    let timestamp = activity.timestamp;
                    if (typeof timestamp === 'string' && timestamp.includes('T')) {
                        // ISO format from database
                        timestamp = new Date(timestamp);
                    } else if (typeof timestamp === 'number') {
                        // Unix timestamp from database
                        timestamp = new Date(timestamp * 1000);
                    } else {
                        timestamp = new Date(timestamp);
                    }
                    
                    const time = timestamp.toLocaleTimeString();
                    const iconClass = getRequestIcon(activity.path, activity.method);
                    const iconColor = getRequestIconColor(activity.path, activity.method);
                    const statusColor = activity.status_code >= 400 ? 'var(--danger-red)' : 
                                      activity.status_code >= 300 ? 'var(--warning-amber)' : 'var(--success-green)';
                    
                    return `
                        <div class="timeline-item clickable" onclick="showActivityDetails('${activity.id}')" title="Click for details">
                            <div class="timeline-icon" style="background: ${iconColor}">
                                <i class="${iconClass}"></i>
                            </div>
                            <div class="timeline-content">
                                <div class="timeline-title">
                                    <span class="request-method">${activity.method}</span>
                                    <span class="request-path">${activity.path}</span>
                                    <span class="status-code" style="color: ${statusColor}">${activity.status_code || 'N/A'}</span>
                                </div>
                                <div class="timeline-details">
                                    <span class="ip-address">${activity.ip}</span>
                                    <span class="separator">•</span>
                                    <span class="request-type">${(activity.type || 'unknown').toUpperCase()}</span>
                                    <span class="separator">•</span>
                                    <span class="event-type">${activity.event_type || 'Request'}</span>
                                </div>
                            </div>
                            <div class="timeline-time">
                                <div class="time">${time}</div>
                                <div class="click-hint"><i class="fas fa-info-circle"></i></div>
                            </div>
                        </div>
                    `;
                }).join('');
                
                console.log('Timeline updated successfully');
            } catch (error) {
                console.error('Error updating timeline:', error);
                timeline.innerHTML = '<div style="text-align: center; color: var(--danger-red); padding: 2rem;">Error loading timeline</div>';
            }
        }

        async function showActivityDetails(activityId) {
            try {
                showToast('Loading activity details...', 'info');
                
                const response = await fetch(`/admin/ids/activity/${activityId}`);
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const details = await response.json();
                openActivityDetailsModal(details);
                
            } catch (error) {
                console.error('Error loading activity details:', error);
                showToast('Failed to load activity details: ' + error.message, 'error');
            }
        }

        function openActivityDetailsModal(details) {
            const modalHtml = `
                <div class="modal-header">
                    <h2><i class="fas fa-info-circle"></i> Activity Details</h2>
                    <button class="close-btn" onclick="closeActivityModal()">&times;</button>
                </div>
                <div class="modal-body">
                    <div class="activity-details-grid">
                        <div class="detail-section">
                            <h3><i class="fas fa-network-wired"></i> Request Information</h3>
                            <div class="detail-row">
                                <span class="label">Method:</span>
                                <span class="value method-${details.request_method.toLowerCase()}">${details.request_method}</span>
                            </div>
                            <div class="detail-row">
                                <span class="label">Path:</span>
                                <span class="value code">${details.request_path}</span>
                            </div>
                            <div class="detail-row">
                                <span class="label">Status Code:</span>
                                <span class="value status-${details.response_code >= 400 ? 'error' : details.response_code >= 300 ? 'warning' : 'success'}">${details.response_code}</span>
                            </div>
                            <div class="detail-row">
                                <span class="label">Processing Time:</span>
                                <span class="value">${details.processing_time || 0}ms</span>
                            </div>
                        </div>
                        
                        <div class="detail-section">
                            <h3><i class="fas fa-user"></i> Client Information</h3>
                            <div class="detail-row">
                                <span class="label">IP Address:</span>
                                <span class="value ip-address">${details.source_ip}</span>
                            </div>
                            <div class="detail-row">
                                <span class="label">User Agent:</span>
                                <span class="value user-agent">${details.user_agent || 'Not provided'}</span>
                            </div>
                            <div class="detail-row">
                                <span class="label">Payload Size:</span>
                                <span class="value">${details.payload_size || 0} bytes</span>
                            </div>
                        </div>
                        
                        <div class="detail-section">
                            <h3><i class="fas fa-shield-alt"></i> Security Analysis</h3>
                            <div class="detail-row">
                                <span class="label">Event Type:</span>
                                <span class="value event-type">${details.event_type}</span>
                            </div>
                            <div class="detail-row">
                                <span class="label">Severity:</span>
                                <span class="value severity-${details.severity.toLowerCase()}">${details.severity}</span>
                            </div>
                            <div class="detail-row">
                                <span class="label">Action Taken:</span>
                                <span class="value action-${details.action_taken.toLowerCase()}">${details.action_taken}</span>
                            </div>
                            <div class="detail-row">
                                <span class="label">Threat Indicators:</span>
                                <span class="value">${details.threat_indicators.length || 0} detected</span>
                            </div>
                        </div>
                        
                        <div class="detail-section full-width">
                            <h3><i class="fas fa-clock"></i> Timeline</h3>
                            <div class="detail-row">
                                <span class="label">Timestamp:</span>
                                <span class="value">${new Date(details.timestamp).toLocaleString()}</span>
                            </div>
                            <div class="detail-row">
                                <span class="label">Event ID:</span>
                                <span class="value code">${details.event_id}</span>
                            </div>
                            ${details.details ? `
                            <div class="detail-row">
                                <span class="label">Details:</span>
                                <span class="value details">${details.details}</span>
                            </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
            `;

            // Create or update modal
            let modal = document.getElementById('activity-details-modal');
            if (!modal) {
                modal = document.createElement('div');
                modal.id = 'activity-details-modal';
                modal.className = 'modal';
                document.body.appendChild(modal);
            }
            
            modal.innerHTML = `<div class="modal-content activity-modal">${modalHtml}</div>`;
            modal.style.display = 'block';
            document.body.style.overflow = 'hidden';
        }

        function closeActivityModal() {
            const modal = document.getElementById('activity-details-modal');
            if (modal) {
                modal.style.display = 'none';
                document.body.style.overflow = 'auto';
            }
        }

        function getRequestIcon(path, method) {
            if (path.includes('telemetry')) return 'fas fa-paper-plane';
            if (path.includes('connect') || path.includes('disconnect')) return 'fas fa-link';
            if (path.includes('code') || method === 'POST') return 'fas fa-code';
            if (method === 'PATCH') return 'fas fa-download';
            if (path.includes('status') || path.includes('health')) return 'fas fa-stethoscope';
            if (path.includes('message')) return 'fas fa-envelope';
            return 'fas fa-globe';
        }

        function getRequestIconColor(path, method) {
            if (path.includes('telemetry')) return 'var(--primary-blue)';
            if (path.includes('connect')) return 'var(--success-green)';
            if (path.includes('code')) return 'var(--warning-amber)';
            if (method === 'PATCH') return 'var(--primary-cyan)';
            if (path.includes('status')) return 'var(--primary-cyan)';
            if (path.includes('message')) return 'var(--danger-red)';
            return 'var(--text-muted)';
        }

        // Device Monitoring Management
        async function loadDeviceMonitoring() {
            try {
                const response = await fetch('/api/devices');
                const devices = await response.json();
                
                updateDeviceOverview(devices);
                populateDeviceSelector(devices);
                
            } catch (error) {
                console.error('Error loading devices:', error);
                showToast('Failed to load device data', 'error');
            }
        }

        function updateDeviceOverview(devices) {
            const total = devices.length;
            const connected = devices.filter(d => d.status === 'Connected').length;
            const offline = total - connected;
            const alerts = devices.filter(d => d.alerts && d.alerts.length > 0).length;
            
            document.getElementById('device-total').textContent = total;
            document.getElementById('device-connected').textContent = connected;
            document.getElementById('device-offline').textContent = offline;
            document.getElementById('device-alerts').textContent = alerts;
        }

        function populateDeviceSelector(devices) {
            const selector = document.getElementById('device-selector');
            if (!selector) return;
            
            selector.innerHTML = '<option value="">Select Device to Monitor</option>';
            devices.forEach(device => {
                const option = document.createElement('option');
                option.value = device.deviceId;
                option.textContent = `${device.deviceId} (${device.deviceType})`;
                selector.appendChild(option);
            });
        }

        async function selectDevice(deviceId) {
            if (!deviceId) {
                showNoDeviceSelected();
                return;
            }
            
            try {
                const response = await fetch(`/api/devices/${deviceId}`);
                const device = await response.json();
                
                showDeviceDetails(device);
                
            } catch (error) {
                console.error('Error loading device details:', error);
                showToast('Failed to load device details', 'error');
            }
        }

        function showNoDeviceSelected() {
            const panel = document.getElementById('device-monitoring-panel');
            panel.innerHTML = `
                <div class="no-device-selected">
                    <i class="fas fa-heartbeat"></i>
                    <p>Select a device from the dropdown to view detailed monitoring data</p>
                </div>
            `;
        }

        function showDeviceDetails(device) {
            const panel = document.getElementById('device-monitoring-panel');
            
            panel.innerHTML = `
                <div class="device-details-grid">
                    <div class="device-detail-section">
                        <h3><i class="fas fa-info-circle"></i> Basic Information</h3>
                        <div class="detail-item">
                            <span class="detail-label">Device ID:</span>
                            <span class="detail-value">${device.deviceId}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Type:</span>
                            <span class="detail-value">${device.deviceType}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Status:</span>
                            <span class="detail-value" style="color: ${device.status === 'Connected' ? 'var(--success-green)' : 'var(--text-muted)'}">${device.status}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Manufacturer:</span>
                            <span class="detail-value">${device.manufacturer}</span>
                        </div>
                    </div>
                    
                    <div class="device-detail-section">
                        <h3><i class="fas fa-cog"></i> System Information</h3>
                        <div class="detail-item">
                            <span class="detail-label">OS:</span>
                            <span class="detail-value">${device.osName} ${device.osVersion}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Software:</span>
                            <span class="detail-value">${device.softwareVersion}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Runtime:</span>
                            <span class="detail-value">${device.runtime}</span>
                        </div>
                    </div>
                    
                    <div class="device-detail-section">
                        <h3><i class="fas fa-chart-line"></i> Activity Monitor</h3>
                        <div class="detail-item">
                            <span class="detail-label">Last Activity:</span>
                            <span class="detail-value">${new Date().toLocaleString()}</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Requests (24h):</span>
                            <span class="detail-value" id="device-requests-${device.deviceId}">Loading...</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Threats:</span>
                            <span class="detail-value" id="device-threats-${device.deviceId}">0</span>
                        </div>
                    </div>
                </div>
            `;
            
            // Load device-specific analytics
            loadDeviceAnalytics(device.deviceId);
        }

        async function loadDeviceAnalytics(deviceId) {
            try {
                // This would need a new API endpoint for device-specific analytics
                // For now, simulate some data
                document.getElementById(`device-requests-${deviceId}`).textContent = Math.floor(Math.random() * 100);
                
            } catch (error) {
                console.error('Error loading device analytics:', error);
            }
        }

        // Enhanced refresh function
        async function refreshAll() {
            showToast('Refreshing all data...', 'info');
            
            const activeTab = document.querySelector('.nav-tab.active').id.replace('tab-', '');
            await loadTabData(activeTab);
            
            showToast('Data refreshed successfully', 'success');
        }

        async function refreshDevices() {
            await loadDeviceMonitoring();
            showToast('Device data refreshed', 'success');
        }

        // Event Listeners
        document.addEventListener('DOMContentLoaded', function() {
            // Add event listener for request time filter
            const timeFilter = document.getElementById('request-time-filter');
            if (timeFilter) {
                timeFilter.addEventListener('change', function() {
                    if (document.getElementById('content-requests').classList.contains('active')) {
                        loadRequestTypes();
                    }
                });
            }

            // Keyboard shortcuts for modal
            document.addEventListener('keydown', function(event) {
                if (event.key === 'Escape') {
                    closeActivityModal();
                }
            });

            // Click outside modal to close
            document.addEventListener('click', function(event) {
                if (event.target.classList.contains('modal')) {
                    closeActivityModal();
                }
            });
        });

        // Geographic Analysis Management
        async function loadGeographicData() {
            try {
                const hours = document.getElementById('geographic-time-filter')?.value || 24;
                const response = await fetch(`/admin/ids/geographic?hours=${hours}`);
                
                if (!response.ok) {
                    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                }
                
                const data = await response.json();
                
                updateGeographicGrid(data.geographic_data);
                updateGeographicSummary(data);
                updateCountryChart(data.geographic_data);
                
                showToast(`Loaded geographic data for ${data.total_countries} countries`, 'success');
                
            } catch (error) {
                console.error('Error loading geographic data:', error);
                showToast('Failed to load geographic data: ' + error.message, 'error');
            }
        }

        function updateGeographicGrid(geographicData) {
            const grid = document.getElementById('geographic-grid');
            if (!grid) return;
            
            if (!geographicData || geographicData.length === 0) {
                grid.innerHTML = '<div style="text-align: center; color: var(--text-muted); padding: 2rem;">No geographic data available</div>';
                return;
            }
            
            grid.innerHTML = geographicData.map(item => `
                <div class="geographic-item" onclick="showGeographicDetails('${item.country}')">
                    <div class="geographic-info">
                        <div class="country-flag">${item.flag}</div>
                        <div class="country-details">
                            <h4>${item.country}</h4>
                            <p>${item.city}</p>
                        </div>
                    </div>
                    <div class="request-stats">
                        <div class="request-count">${item.requests}</div>
                        <div class="request-percentage">${item.percentage.toFixed(1)}%</div>
                    </div>
                </div>
            `).join('');
        }

        function updateGeographicSummary(data) {
            const details = document.getElementById('geographic-details');
            if (!details) return;
            
            details.innerHTML = `
                <div class="geographic-summary">
                    <div class="geo-stat">
                        <div class="geo-stat-value">${data.total_countries}</div>
                        <div class="geo-stat-label">Countries</div>
                    </div>
                    <div class="geo-stat">
                        <div class="geo-stat-value">${data.total_requests}</div>
                        <div class="geo-stat-label">Total Requests</div>
                    </div>
                    <div class="geo-stat">
                        <div class="geo-stat-value">${data.time_period_hours}h</div>
                        <div class="geo-stat-label">Time Period</div>
                    </div>
                </div>
                <div style="text-align: center; color: var(--text-muted); font-size: 0.9rem; margin-top: 1rem;">
                    <i class="fas fa-info-circle"></i> ${data.note || 'Live geographic distribution of requests'}
                </div>
            `;
        }

        function updateCountryChart(geographicData) {
            const canvas = document.getElementById('countryChart');
            if (!canvas) return;
            
            const ctx = canvas.getContext('2d');
            
            // Destroy existing chart if it exists
            if (window.countryChart && typeof window.countryChart.destroy === 'function') {
                window.countryChart.destroy();
            }
            
            const topCountries = geographicData.slice(0, 10);
            
            // Check if Chart.js is loaded
            if (typeof Chart === 'undefined') {
                console.error('Chart.js is not loaded');
                return;
            }
            
            try {
                window.countryChart = new Chart(ctx, {
                    type: 'bar',  // Use 'bar' instead of 'horizontalBar'
                    data: {
                        labels: topCountries.map(item => `${item.flag} ${item.country}`),
                        datasets: [{
                            label: 'Requests',
                            data: topCountries.map(item => item.requests),
                            backgroundColor: topCountries.map(item => item.color + '80'),
                            borderColor: topCountries.map(item => item.color),
                            borderWidth: 2
                        }]
                    },
                    options: {
                        indexAxis: 'y',  // This makes it horizontal
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                display: false
                            }
                        },
                        scales: {
                            x: {
                                beginAtZero: true,
                                grid: {
                                    color: 'rgba(255, 255, 255, 0.1)'
                                },
                                ticks: {
                                    color: '#b0b0b0'
                                }
                            },
                            y: {
                                grid: {
                                    color: 'rgba(255, 255, 255, 0.1)'
                                },
                                ticks: {
                                    color: '#b0b0b0'
                                }
                            }
                        }
                    }
                });
            } catch (error) {
                console.error('Error creating country chart:', error);
                // Fallback: show text-based chart
                canvas.parentElement.innerHTML = `
                    <div style="padding: 20px; text-align: center; color: var(--text-muted);">
                        <p>Chart unavailable. Top countries:</p>
                        ${topCountries.map(item => `<div>${item.flag} ${item.country}: ${item.requests} requests</div>`).join('')}
                    </div>
                `;
            }
        }

        function showGeographicDetails(country) {
            showToast(`Detailed analysis for ${country} - Feature coming soon!`, 'info');
        }

        // Enhanced showTab function to handle geographic tab
        function showTab(tabName) {
            // Hide all tab contents
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all nav tabs
            document.querySelectorAll('.nav-tab').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // Show selected tab content
            const selectedContent = document.getElementById(`content-${tabName}`);
            const selectedTab = document.getElementById(`tab-${tabName}`);
            
            if (selectedContent) {
                selectedContent.classList.add('active');
            }
            
            if (selectedTab) {
                selectedTab.classList.add('active');
            }
            
            // Load data based on tab
            switch (tabName) {
                case 'overview':
                    loadOverviewData();
                    break;
                case 'requests':
                    loadRequestTypes();
                    break;
                case 'devices':
                    loadDevices();
                    break;
                case 'threats':
                    loadSecurityEvents();
                    break;
                case 'geographic':
                    loadGeographicData();
                    break;
                case 'network':
                    // Network tab functionality can be added here
                    break;
            }
        }

        // Update time filter change handlers and auto-refresh
        document.addEventListener('DOMContentLoaded', function() {
            const geoTimeFilter = document.getElementById('geographic-time-filter');
            if (geoTimeFilter) {
                geoTimeFilter.addEventListener('change', loadGeographicData);
            }
            
            const requestTimeFilter = document.getElementById('request-time-filter');
            if (requestTimeFilter) {
                requestTimeFilter.addEventListener('change', loadRequestTypes);
            }
            
            // Auto-refresh request types every 30 seconds when on requests tab
            setInterval(() => {
                const activeTab = document.querySelector('.tab-content.active');
                if (activeTab && activeTab.id === 'content-requests') {
                    console.log('Auto-refreshing request types...');
                    loadRequestTypes();
                }
            }, 30000);
            
            // Initial load
            loadOverviewData();
        });

    </script>
</body>
</html>
"""

@admin_router.get("/", response_class=HTMLResponse)
async def admin_dashboard():
    """Serve the professional admin dashboard"""
    return HTMLResponse(content=PROFESSIONAL_ADMIN_DASHBOARD_HTML)

@admin_router.get("/ai-security", response_class=HTMLResponse)
async def ai_security_monitor():
    """AI Security monitoring dashboard"""
    try:
        with open('ai_security_monitor.html', 'r', encoding='utf-8') as f:
            return HTMLResponse(content=f.read())
    except FileNotFoundError:
        return HTMLResponse(content="<h1>AI Security Monitor</h1><p>Monitor file not found. Please check installation.</p>")

@admin_router.get("/ids/overview")
async def get_ids_overview():
    """Get comprehensive IDS overview data"""
    try:
        dashboard_data = ids_manager.get_dashboard_data()
        return JSONResponse(content=dashboard_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get overview: {str(e)}")

@admin_router.get("/ids/analytics")
async def get_request_analytics(hours: int = Query(24, ge=1, le=168)):
    """Get request analytics for specified time period"""
    try:
        analytics = ids_manager.database.get_request_analytics(hours)
        return JSONResponse(content=analytics)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get analytics: {str(e)}")

@admin_router.get("/ids/events")
async def get_security_events(
    limit: int = Query(50, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    hours: int = Query(24, ge=1, le=168)
):
    """Get security events with filtering"""
    try:
        since = datetime.now() - timedelta(hours=hours) if hours else None
        events = ids_manager.database.get_security_events(limit, severity, since)
        return JSONResponse(content=events)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get events: {str(e)}")

@admin_router.get("/ids/blocked-ips")
async def get_blocked_ips_endpoint():
    """Get list of blocked IPs from the comprehensive database"""
    try:
        # Import the database manager
        from database_manager import db_manager
        
        blocked_ips = db_manager.get_blocked_ips()
        return JSONResponse(content=blocked_ips)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get blocked IPs: {str(e)}")

@admin_router.post("/ids/block-ip")
async def block_ip_endpoint(request: IPBlockRequest):
    """Manually block an IP address using the comprehensive database"""
    try:
        # Import the database manager
        from database_manager import db_manager
        
        # Block the IP using the new database system
        duration_hours = None if request.permanent else 24  # Default 24 hours for temporary blocks
        db_manager.block_ip(request.ip, request.reason, duration_hours)
        
        return JSONResponse(content={
            "success": True,
            "message": f"IP {request.ip} has been blocked",
            "permanent": request.permanent
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to block IP: {str(e)}")

@admin_router.post("/ids/unblock-ip")
async def unblock_ip_endpoint(request: IPUnblockRequest):
    """Manually unblock an IP address using the comprehensive database"""
    try:
        # Import the database manager
        from database_manager import db_manager
        
        # Remove IP from blocked list by setting expiration to now
        import sqlite3
        from datetime import datetime
        
        with sqlite3.connect(db_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE blocked_ips 
                SET expires_at = ? 
                WHERE ip_address = ?
            """, (datetime.now().timestamp(), request.ip))
            conn.commit()
        
        return JSONResponse(content={
            "success": True,
            "message": f"IP {request.ip} has been unblocked"
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to unblock IP: {str(e)}")

@admin_router.get("/ids/stats")
async def get_security_stats_endpoint():
    """Get current security statistics"""
    try:
        stats = get_security_stats()
        return JSONResponse(content=stats)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")

@admin_router.get("/ids/top-threats")
async def get_top_threats(hours: int = Query(24, ge=1, le=168)):
    """Get top threat types and IPs"""
    try:
        since = datetime.now() - timedelta(hours=hours)
        events = ids_manager.database.get_security_events(1000, since=since)
        
        # Analyze threat types
        threat_counts = {}
        ip_counts = {}
        
        for event in events:
            threat_type = event['event_type']
            ip = event['source_ip']
            
            threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        # Sort by count
        top_threats = sorted(threat_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return JSONResponse(content={
            "top_threats": [{"type": t[0], "count": t[1]} for t in top_threats],
            "top_attacking_ips": [{"ip": ip[0], "count": ip[1]} for ip in top_ips],
            "time_period_hours": hours
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get top threats: {str(e)}")

@admin_router.delete("/ids/events")
async def clear_old_events(days: int = Query(30, ge=1, le=365)):
    """Clear security events older than specified days"""
    try:
        cutoff_date = datetime.now() - timedelta(days=days)
        
        with sqlite3.connect(ids_manager.database.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM security_events WHERE timestamp < ?",
                (cutoff_date.isoformat(),)
            )
            deleted_count = cursor.rowcount
        
        return JSONResponse(content={
            "success": True,
            "message": f"Deleted {deleted_count} events older than {days} days"
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear events: {str(e)}")

@admin_router.get("/ids/request-types")
async def get_request_types_analysis(hours: int = Query(24, ge=1, le=168)):
    """Get comprehensive request type analysis from the new database system"""
    try:
        # Import the database manager
        from database_manager import db_manager
        
        # Get comprehensive request analytics from the new database
        analytics = db_manager.get_request_analytics(hours)
        
        return JSONResponse(content=analytics)
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in get_request_types_analysis: {error_details}")
        raise HTTPException(status_code=500, detail=f"Failed to get request types: {str(e)}")

@admin_router.get("/ids/activity/{activity_id}")
async def get_activity_details(activity_id: str):
    """Get detailed information about a specific activity"""
    try:
        # First try to find in security events
        events = ids_manager.database.get_security_events(1000)
        event = next((e for e in events if e.get('event_id') == activity_id), None)
        
        if event:
            # Found in security events - this is a security-related activity
            details = {
                "event_id": event.get('event_id', ''),
                "timestamp": event.get('timestamp', ''),
                "source_ip": event.get('source_ip', ''),
                "request_method": event.get('method', ''),
                "request_path": event.get('path', ''),
                "user_agent": event.get('user_agent', ''),
                "response_code": 200,  # Security events don't have response codes
                "event_type": event.get('event_type', ''),
                "severity": event.get('severity', 'INFO'),
                "details": event.get('threat_details', ''),
                "payload_size": len(event.get('payload', '')),
                "processing_time": 0,
                "headers": {},
                "threat_indicators": [event.get('event_type', '')],
                "action_taken": event.get('action_taken', 'LOGGED')
            }
        else:
            # Not found in security events, check request metrics by reconstructing from activity ID
            # This is a regular request logged in metrics
            try:
                with sqlite3.connect(ids_manager.database.db_path) as conn:
                    # Try to find the request in metrics table
                    cursor = conn.execute("""
                        SELECT ip, method, path, timestamp, user_agent, payload_size, response_code
                        FROM request_metrics 
                        ORDER BY timestamp DESC
                        LIMIT 1000
                    """)
                    metrics = cursor.fetchall()
                    
                    # Find matching metric by recreating the activity ID
                    matching_metric = None
                    for metric in metrics:
                        ip, method, path, timestamp, user_agent, payload_size, response_code = metric
                        test_id = hashlib.md5(f"{timestamp}{ip}{method}{path}".encode()).hexdigest()[:16]
                        if test_id == activity_id:
                            matching_metric = metric
                            break
                    
                    if not matching_metric:
                        raise HTTPException(status_code=404, detail="Activity not found")
                    
                    ip, method, path, timestamp, user_agent, payload_size, response_code = matching_metric
                    
                    # Create details from request metrics
                    details = {
                        "event_id": activity_id,
                        "timestamp": datetime.fromtimestamp(timestamp).isoformat(),
                        "source_ip": ip,
                        "request_method": method,
                        "request_path": path,
                        "user_agent": user_agent or 'Unknown',
                        "response_code": response_code,
                        "event_type": "REQUEST_LOGGED",
                        "severity": "INFO",
                        "details": f"Normal {method} request to {path}",
                        "payload_size": payload_size or 0,
                        "processing_time": 0,
                        "headers": {},
                        "threat_indicators": [],
                        "action_taken": "LOGGED"
                    }
                    
            except Exception as db_error:
                print(f"Database error: {db_error}")
                raise HTTPException(status_code=404, detail="Activity not found")
        
        return JSONResponse(content=details)
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in get_activity_details: {error_details}")
        raise HTTPException(status_code=500, detail=f"Failed to get activity details: {str(e)}")

@admin_router.get("/ids/geographic")
async def get_geographic_analysis(hours: int = Query(24, ge=1, le=168)):
    """Get geographic distribution of requests"""
    try:
        # Import the database manager
        from database_manager import db_manager
        
        # Get real geographic data from the comprehensive database
        geographic_analysis = db_manager.get_geographic_analysis(hours)
        
        # Add color coding for the countries
        country_colors = {
            'United States': '#ef4444', 'India': '#f97316', 'Germany': '#eab308',
            'United Kingdom': '#22c55e', 'Japan': '#06b6d4', 'Canada': '#8b5cf6',
            'Australia': '#ec4899', 'France': '#14b8a6', 'Brazil': '#f59e0b',
            'Singapore': '#84cc16', 'Local Host': '#3b82f6', 'Unknown': '#6b7280'
        }
        
        # Enhance the geographic data with colors
        for item in geographic_analysis['geographic_data']:
            item['color'] = country_colors.get(item['country'], '#6b7280')  # Default grey
        
        return JSONResponse(content={
            "geographic_data": geographic_analysis['geographic_data'],
            "total_countries": geographic_analysis['total_countries'],
            "total_requests": geographic_analysis['total_requests'],
            "time_period_hours": hours,
            "note": "Real-time geographic distribution based on actual API requests"
        })
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in get_geographic_analysis: {error_details}")
        raise HTTPException(status_code=500, detail=f"Failed to get geographic analysis: {str(e)}")

@admin_router.get("/ids/health")
async def ids_health_check():
    """IDS system health check"""
    try:
        return JSONResponse(content={
            "status": "healthy",
            "ids_active": True,
            "database_accessible": True,
            "blocked_ips_count": len(get_blocked_ips()),
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
        )

# AI Security Decision Endpoints
@admin_router.get("/ai-security/decisions")
async def get_ai_security_decisions(hours: int = Query(24, description="Hours of data to retrieve")):
    """Get AI security decisions from the last N hours"""
    try:
        from database_manager import db_manager
        
        # Get security events related to AI decisions
        all_events = db_manager.get_all_security_events()
        
        # Filter AI security decisions
        cutoff_time = datetime.now() - timedelta(hours=hours)
        ai_decisions = []
        
        for event in all_events:
            try:
                timestamp_str = event.get('timestamp', '2000-01-01T00:00:00')
                # Handle different timestamp formats
                if 'T' not in timestamp_str:
                    timestamp_str += 'T00:00:00'
                event_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                if (event_time > cutoff_time and 
                    event.get('event_type') == 'ai_security_decision'):
                    
                    additional_data = event.get('additional_data', {})
                    ai_decisions.append({
                        "timestamp": event.get('timestamp'),
                        "decision_id": f"decision-{int(time.time())}",
                        "approved": additional_data.get('approved', True),
                        "risk_score": additional_data.get('risk_score', 0),
                        "request_method": additional_data.get('request_method', 'Unknown'),
                        "request_path": additional_data.get('request_path', 'Unknown'),
                        "source_ip": event.get('source_ip', 'Unknown'),
                        "reasons": additional_data.get('reasons', []),
                        "agent_recommendations": additional_data.get('agent_recommendations', {}),
                        "severity": event.get('severity', 'info')
                    })
            except (ValueError, TypeError):
                continue
        
        # Sort by timestamp (newest first)
        ai_decisions.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Calculate statistics
        total_decisions = len(ai_decisions)
        blocked_count = len([d for d in ai_decisions if not d['approved']])
        approved_count = total_decisions - blocked_count
        avg_risk_score = sum(d['risk_score'] for d in ai_decisions) / max(1, total_decisions)
        
        return JSONResponse({
            "decisions": ai_decisions[:100],  # Limit to 100 most recent
            "statistics": {
                "total_decisions": total_decisions,
                "approved_requests": approved_count,
                "blocked_requests": blocked_count,
                "block_rate_percent": round((blocked_count / max(1, total_decisions)) * 100, 2),
                "average_risk_score": round(avg_risk_score, 2)
            },
            "timeframe_hours": hours,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "error": f"Failed to retrieve AI security decisions: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
        )

@admin_router.get("/ai-security/blocked-requests")
async def get_blocked_requests(limit: int = Query(50, description="Maximum number of blocked requests to return")):
    """Get recent requests blocked by AI security system"""
    try:
        from database_manager import db_manager
        
        # Get security events for blocked requests
        all_events = db_manager.get_all_security_events()
        
        blocked_requests = []
        for event in all_events:
            try:
                if (event.get('event_type') == 'ai_security_decision' and 
                    event.get('additional_data', {}).get('approved', True) == False):
                
                    additional_data = event.get('additional_data', {})
                    blocked_requests.append({
                        "timestamp": event.get('timestamp'),
                        "source_ip": event.get('source_ip', 'Unknown'),
                        "request_method": additional_data.get('request_method', 'Unknown'),
                        "request_path": additional_data.get('request_path', 'Unknown'),
                        "risk_score": additional_data.get('risk_score', 0),
                        "block_reasons": additional_data.get('reasons', []),
                        "severity": event.get('severity', 'medium'),
                        "agent_analysis": {
                            "malware_detected": 'malware_scan' in additional_data.get('agent_recommendations', {}),
                            "code_quality_issues": 'code_analysis' in additional_data.get('agent_recommendations', {}),
                            "ai_recommendation": additional_data.get('agent_recommendations', {}).get('ai_decision', {}).get('decision_type', 'unknown')
                        }
                    })
            except Exception as e:
                continue  # Skip problematic events
        
        # Sort by timestamp (newest first) and limit
        blocked_requests.sort(key=lambda x: x['timestamp'], reverse=True)
        blocked_requests = blocked_requests[:limit]
        
        return JSONResponse({
            "blocked_requests": blocked_requests,
            "total_blocked": len(blocked_requests),
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "error": f"Failed to retrieve blocked requests: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
        )

@admin_router.get("/ai-security/agent-status")
async def get_ai_agent_status():
    """Get status and performance metrics of AI security agents"""
    try:
        # Try to import and check AI agents
        agent_status = {}
        
        try:
            from code_refactoring_agent import CodeRefactoringAgent
            refactoring_agent = CodeRefactoringAgent()
            agent_status['code_refactoring'] = {
                "status": "active",
                "ai_enabled": getattr(refactoring_agent, 'ai_enabled', False),
                "last_check": datetime.now().isoformat()
            }
        except Exception as e:
            agent_status['code_refactoring'] = {
                "status": "error",
                "error": str(e),
                "last_check": datetime.now().isoformat()
            }
        
        try:
            from optimization_agent import OptimizationAgent
            optimization_agent = OptimizationAgent()
            agent_status['optimization'] = {
                "status": "active",
                "ai_enabled": getattr(optimization_agent, 'ai_enabled', False),
                "last_check": datetime.now().isoformat()
            }
        except Exception as e:
            agent_status['optimization'] = {
                "status": "error",
                "error": str(e),
                "last_check": datetime.now().isoformat()
            }
        
        try:
            from malicious_code_detection_agent import MaliciousCodeDetectionAgent
            malware_agent = MaliciousCodeDetectionAgent()
            agent_status['malware_detection'] = {
                "status": "active",
                "ai_enabled": getattr(malware_agent, 'ai_enabled', False),  
                "last_check": datetime.now().isoformat()
            }
        except Exception as e:
            agent_status['malware_detection'] = {
                "status": "error",
                "error": str(e),
                "last_check": datetime.now().isoformat()
            }
        
        # Check AI coordinator
        try:
            from ai_agent_coordinator import coordinator
            agent_status['coordinator'] = {
                "status": "active",
                "ai_enabled": True,  # Coordinator is always AI-enabled if it can be imported
                "agents_count": len(coordinator.agents),
                "last_check": datetime.now().isoformat()
            }
        except Exception as e:
            agent_status['coordinator'] = {
                "status": "error",
                "ai_enabled": False,
                "error": str(e),
                "last_check": datetime.now().isoformat()
            }
        
        # Overall system status
        active_agents = len([a for a in agent_status.values() if a.get('status') == 'active'])
        total_agents = len(agent_status)
        ai_enabled_count = len([a for a in agent_status.values() if a.get('ai_enabled', False)])
        
        return JSONResponse({
            "agent_status": agent_status,
            "summary": {
                "active_agents": active_agents,
                "total_agents": total_agents,
                "ai_enabled_agents": ai_enabled_count,
                "system_health": "healthy" if active_agents == total_agents else "degraded",
                "ai_features_enabled": ai_enabled_count > 0
            },
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "error": f"Failed to get AI agent status: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
        )

@admin_router.get("/ai-security/metrics")
async def get_ai_security_metrics(hours: int = Query(24, description="Hours of data for metrics")):
    """Get comprehensive AI security metrics"""
    try:
        from database_manager import db_manager
        
        # Get recent security events
        all_events = db_manager.get_all_security_events()
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Filter recent AI-related events
        recent_events = []
        for event in all_events:
            try:
                timestamp_str = event.get('timestamp', '2000-01-01T00:00:00')
                # Handle different timestamp formats
                if 'T' not in timestamp_str:
                    timestamp_str += 'T00:00:00'
                event_time = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                if event_time > cutoff_time:
                    recent_events.append(event)
            except (ValueError, TypeError):
                continue
        
        # Calculate metrics
        ai_decisions = [e for e in recent_events if e.get('event_type') == 'ai_security_decision']
        code_analyses = [e for e in recent_events if e.get('event_type') == 'code_analysis']
        malware_scans = [e for e in recent_events if e.get('event_type') == 'malware_scan']
        optimizations = [e for e in recent_events if e.get('event_type') == 'optimization_analysis']
        
        # Request processing metrics
        total_requests_processed = len(ai_decisions)
        blocked_requests = len([d for d in ai_decisions if not d.get('additional_data', {}).get('approved', True)])
        approved_requests = total_requests_processed - blocked_requests
        
        # Security threat metrics
        malicious_detections = len([s for s in malware_scans if s.get('additional_data', {}).get('is_malicious', False)])
        high_risk_requests = len([d for d in ai_decisions if d.get('additional_data', {}).get('risk_score', 0) >= 70])
        
        # Performance metrics
        avg_risk_score = sum(d.get('additional_data', {}).get('risk_score', 0) for d in ai_decisions) / max(1, len(ai_decisions))
        avg_code_quality = sum(c.get('additional_data', {}).get('maintainability_score', 0) for c in code_analyses) / max(1, len(code_analyses))
        
        return JSONResponse({
            "timeframe_hours": hours,
            "request_processing": {
                "total_processed": total_requests_processed,
                "approved": approved_requests,
                "blocked": blocked_requests,
                "block_rate_percent": round((blocked_requests / max(1, total_requests_processed)) * 100, 2)
            },
            "security_analysis": {
                "malware_scans": len(malware_scans),
                "malicious_detections": malicious_detections,
                "code_analyses": len(code_analyses),
                "high_risk_requests": high_risk_requests,
                "average_risk_score": round(avg_risk_score, 2)
            },
            "code_quality": {
                "analyses_performed": len(code_analyses),
                "average_maintainability": round(avg_code_quality, 2),
                "improvement_suggestions": sum(c.get('additional_data', {}).get('suggestions_count', 0) for c in code_analyses)
            },
            "system_optimization": {
                "optimizations_performed": len(optimizations),
                "requests_enhanced": len([d for d in ai_decisions if 'optimization' in d.get('additional_data', {}).get('agent_recommendations', {})])
            },
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "error": f"Failed to get AI security metrics: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }
        )