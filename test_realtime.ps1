# PowerShell script to test real-time AI security updates
$headers = @{
    "Content-Type" = "application/json"
    "X-Force-AI-Analysis" = "true"
}

# Code execution request (correct format)
$body = @{
    deviceId = "med-ecg-001"
    code = "print('Getting temperature reading...'); temperature = get_sensor_data('temperature'); print(f'Temperature: {temperature}°C')"
    language = "python"
    parameters = @{}
} | ConvertTo-Json

Write-Host "🧪 Sending code execution request to trigger AI analysis..."
try {
    $response = Invoke-RestMethod -Uri "http://127.0.0.1:8001/api/devices/med-ecg-001/code" -Method POST -Headers $headers -Body $body
    Write-Host "✅ Code execution request sent successfully"
    Write-Host "Response: $($response | ConvertTo-Json -Depth 3)"
} catch {
    Write-Host "❌ Request failed: $($_.Exception.Message)"
}

# Telemetry request (correct format)
$body2 = @{
    deviceIds = @("med-ecg-002", "med-pump-001")
    messageCount = 2
    interval = 1.0
} | ConvertTo-Json

Write-Host "`n🧪 Sending telemetry request..."
try {
    $response2 = Invoke-RestMethod -Uri "http://127.0.0.1:8001/api/telemetry/send" -Method POST -Headers $headers -Body $body2
    Write-Host "✅ Telemetry request sent successfully"
    Write-Host "Response: $($response2 | ConvertTo-Json -Depth 3)"
} catch {
    Write-Host "❌ Telemetry request failed: $($_.Exception.Message)"
}

Write-Host "`n📊 Check the dashboard now: http://127.0.0.1:8001/admin/ai-security"