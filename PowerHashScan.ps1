# Configuration
$virusTotalApiKey = "Your_VirusTotal_API_Key"
$googleSafeBrowsingApiKey = "Your_GoogleSafeBrowsing_API_Key"
$hybridAnalysisApiKey = "Your_HybridAnalysis_API_Key"

# Function to get file hashes in a specified directory
function Get-FileHashes {
    param (
        [string]$directory
    )
    
    $hashes = @()

    Get-ChildItem -Path $directory -File | ForEach-Object {
        $filePath = $_.FullName
        $hash = Get-FileHash -Path $filePath -Algorithm SHA256
        $hashes += $hash.Hash
    }

    return $hashes
}

# Function to send hash to VirusTotal
function Check-VirusTotal {
    param (
        [string]$hash
    )

    $url = "https://www.virustotal.com/vtapi/v2/file/report"
    $params = @{
        apikey = $virusTotalApiKey
        resource = $hash
    }

    $response = Invoke-RestMethod -Uri $url -Method Get -Body $params
    return $response
}

# Function to send hash to Google Safe Browsing (URL-based)
function Check-GoogleSafeBrowsing {
    param (
        [string]$hash
    )

    $url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$googleSafeBrowsingApiKey"
    $body = @{
        "client" = @{
            "clientId"      = "your-client-id"
            "clientVersion" = "1.0"
        }
        "threatInfo" = @{
            "threatTypes"      = @("MALWARE", "SOCIAL_ENGINEERING")
            "platformTypes"    = @("WINDOWS")
            "threatEntryTypes" = @("URL")
            "threatEntries"    = @(@{ "url" = "file:///$hash" })
        }
    }

    $response = Invoke-RestMethod -Uri $url -Method Post -Body ($body | ConvertTo-Json)
    return $response
}

# Function to send hash to Hybrid Analysis
function Check-HybridAnalysis {
    param (
        [string]$hash
    )

    $url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    $headers = @{
        "api-key" = $hybridAnalysisApiKey
    }

    $params = @{
        hash = $hash
    }

    $response = Invoke-RestMethod -Uri $url -Method Post -Headers $headers -Body $params
    return $response
}

# Main function to process the hashes
function Process-Hashes {
    param (
        [string]$directory
    )

    $hashes = Get-FileHashes -directory $directory

    foreach ($hash in $hashes) {
        Write-Host "Checking VirusTotal for hash: $hash"
        $vtResult = Check-VirusTotal -hash $hash
        Write-Host "VirusTotal result: $($vtResult | ConvertTo-Json)"

        Write-Host "Checking Google Safe Browsing for hash: $hash"
        $gsbResult = Check-GoogleSafeBrowsing -hash $hash
        Write-Host "Google Safe Browsing result: $($gsbResult | ConvertTo-Json)"

        Write-Host "Checking Hybrid Analysis for hash: $hash"
        $haResult = Check-HybridAnalysis -hash $hash
        Write-Host "Hybrid Analysis result: $($haResult | ConvertTo-Json)"
    }
}

# Specify the directory to scan
$directoryToScan = "C:\Path\To\Your\Directory"
Process-Hashes -directory $directoryToScan
