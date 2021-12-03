<#  
    Title:          VMware Carbon Black Cloud - Endpoint Standard Data Connector
    Language:       PowerShell
    Version:        1.0
    Author:         Microsoft
    Last Modified:  5/19/2020
    Comment:        Inital Release

    DESCRIPTION
    This Function App calls the VMware Carbon Black Cloud - Endpoint Standard (formerly CB Defense) REST API (https://developer.carbonblack.com/reference/carbon-black-cloud/cb-defense/latest/rest-api/) to pull the Carbon Black
    Audit, Notification and Event logs. The response from the CarbonBlack API is recieved in JSON format. This function will build the signature and authorization header 
    needed to post the data to the Log Analytics workspace via the HTTP Data Connector API. The Function App will post each log type to their individual tables in Log Analytics, for example,
    CarbonBlackAuditLogs_CL, CarbonBlackNotifications_CL and CarbonBlackEvents_CL.
#>
# Input bindings are passed in via param block.
param($Timer)

#Requires -Modules @{ModuleName='AWS.Tools.Common';ModuleVersion='4.1.14'}
#Requires -Modules @{ModuleName='AWS.Tools.S3';ModuleVersion='4.1.14'}

# Get the current universal time in the default string format
$currentUTCtime = (Get-Date).ToUniversalTime()
$logAnalyticsUri = $env:logAnalyticsUri

# The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}

Function EventsFieldsMapping {
    Param (
        $events
    )
    Write-Host "Started Field Mapping for event logs"
    
    $fieldMappings = @{
        'shortDescription' = 'event_description'
        'createTime' = 'backend_timestamp'
        'eventId' = 'event_id'
        'longDescription' = 'event_description'
        'eventTime' = 'device_timestamp'
        'securityEventCode' = 'alert_id'
        'eventType' = 'type'
        'incidentId' = 'alert_id'
        'deviceDetails_deviceIpAddress' = 'device_external_ip'
        'deviceDetails_deviceIpV4Address' = 'device_external_ip'
        'deviceDetails_deviceId' = 'device_id'
        'deviceDetails_deviceName' = 'device_name'
        'deviceDetails_deviceType' = 'device_os'
        'deviceDetails_msmGroupName' = 'device_group'
        'netFlow_peerFqdn' = 'netconn_domain'
        'netFlow_peerIpAddress' = 'remote_ip'
        'processDetails_name' = 'process_name'
        'processDetails_commandLine' = 'process_cmdline'
        'processDetails_fullUserName' ='process_username'
        'processDetails_processId'='process_pid'
        'processDetails_parentCommandLine' = 'process_cmdline'
        'processDetails_parentName' = 'parent_path'
        'processDetails_parentPid' = 'parent_pid'
        'processDetails_targetCommandLine' = 'target_cmdline'
    }
    
    $fieldMappings.GetEnumerator() | ForEach-Object {
        if (!$events.ContainsKey($_.Name))
        {
            $events[$_.Name] = $events[$_.Value]
        }
    }
}

Function AlertsFieldsMapping {
    Param (
        $alerts
    )
    Write-Host "Started Field Mapping for alert logs"
    
    $fieldMappings = @{
        'threatHunterInfo_summary' = 'reason_code'
        'threatHunterInfo_time' = 'create_time'
        'threatHunterInfo_indicators' = 'threat_indicators'
        'threatHunterInfo_count' = '0'
        'threatHunterInfo_dismissed' = 'workflow.state'
        'threatHunterInfo_firstActivityTime' = 'first_event_time'
        'threatHunterInfo_policyId' = 'process_guid'
        'threatHunterInfo_processPath' = 'severity'
        'threatHunterInfo_reportName' = 'report_name'
        'threatHunterInfo_reportId' = 'report_id'
        'threatHunterInfo_reputation' = 'threat_cause_reputation'
        'threatHunterInfo_responseAlarmId' = 'id'
        'threatHunterInfo_responseSeverity' = 'Severity'
        'threatHunterInfo_runState' = 'run_state'
        "threatHunterInfo_sha256_" = "threat_cause_actor_sha256"
        "threatHunterInfo_status" = "status"
        "threatHunterInfo_targetPriority" = "target_value"
        "threatHunterInfo_threatCause_reputation" = "threat_cause_reputation"
        "threatHunterInfo_threatCause_actor" = "threat_cause_actor_sha256"
        "threatHunterInfo_threatCause_actorName" = "threat_cause_actor_name"
        "threatHunterInfo_threatCause_reason" = "reason_code"
        "threatHunterInfo_threatCause_threatCategory" = "threat_cause_threat_category"
        "threatHunterInfo_threatCause_originSourceType" = "threat_cause_vector"
        "threatHunterInfo_threatId" = "threat_id"
        "threatHunterInfo_lastUpdatedTime" = "last_update_time"
        #"threatHunterInfo_orgId_d": "12261",
        "threatInfo_incidentId" = "legacy_alert_id"
        "threatInfo_score" = "severity"
        "threatInfo_summary" = "reason"
        #"threatInfo_time_d": "null",
        "threatInfo_indicators" = "threat_indicators"
        "threatInfo_threatCause_reputation" = "threat_cause_reputation"
        "threatInfo_threatCause_actor" = "threat_cause_actor_sha256"
        "threatInfo_threatCause_reason" = "reason_code"
        "threatInfo_threatCause_threatCategory" = "threat_cause_threat_catego"
        "threatInfo_threatCause_actorProcessPPid" = "threat_cause_actor_process_pid"
        "threatInfo_threatCause_causeEventId" = "threat_cause_cause_event_id"
        "threatInfo_threatCause_originSourceType" = "threat_cause_vector"
        "url" = "alert_url"
        "eventTime" = "create_time"
        #"eventDescription_s": "[AzureSentinel] [Carbon Black has detected a threat against your company.] [https://defense-prod05.conferdeploy.net#device/20602996/incident/NE2F3D55-013a6074-000013b0-00000000-1d634654ecf865f-GUWNtEmJQhKmuOTxoRV8hA-6e5ae551-1cbb-45b3-b7a1-1569c0458f6b] [Process powershell.exe was detected by the report \"Execution - Powershell Execution With Unrestriced or Bypass Flags Detected\" in watchlist \"Carbon Black Endpoint Visibility\"] [Incident id: NE2F3D55-013a6074-000013b0-00000000-1d634654ecf865f-GUWNtEmJQhKmuOTxoRV8hA-6e5ae551-1cbb-45b3-b7a1-1569c0458f6b] [Threat score: 6] [Group: Standard] [Email: sanitized@sanitized.com] [Name: Endpoint2] [Type and OS: WINDOWS pscr-sensor] [Severity: 6]\n",
        "deviceInfo_deviceId" = "device_id"
        "deviceInfo_deviceName" = "device_name"
        "deviceInfo_groupName" = "policy_name"
        "deviceInfo_email" = "device_username"
        "deviceInfo_deviceType" = "device_os"
        "deviceInfo_deviceVersion" = "device_os_version"
        "deviceInfo_targetPriorityType" = "target_value"
       # "deviceInfo_targetPriorityCode_d": "0",
        "deviceInfo_uemId" = "device_uem_id"
        "deviceInfo_internalIpAddress" = "device_internal_ip"
        "deviceInfo_externalIpAddress" = "device_external_ip"
        #"ruleName_s": "AzureSentinel",
        #"type_s": "THREAT_HUNTER",
        #"notifications_s": "",
        #"success_b": "null",
        #"Message": "",
        #"Type": "CarbonBlackNotifications_CL",
        #"_ResourceId": "
    }
    
    $fieldMappings.GetEnumerator() | ForEach-Object {
        if (!$alerts.ContainsKey($_.Name))
        {
            $alerts[$_.Name] = $alerts[$_.Value]
        }
    }
}

Function Expand-GZipFile {
    Param(
        $infile,
        $outfile       
    )
	Write-Host "Processing Expand-GZipFile for: infile = $infile, outfile = $outfile"
    $inputfile = New-Object System.IO.FileStream $infile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)	
    $output = New-Object System.IO.FileStream $outfile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)	
    $gzipStream = New-Object System.IO.Compression.GzipStream $inputfile, ([IO.Compression.CompressionMode]::Decompress)	
	
    $buffer = New-Object byte[](1024)	
    while ($true) {
        $read = $gzipstream.Read($buffer, 0, 1024)		
        if ($read -le 0) { break }		
		$output.Write($buffer, 0, $read)		
	}
	
    $gzipStream.Close()
    $output.Close()
    $inputfile.Close()
}

# The function will call the Carbon Black API and retrieve the Audit, Event, and Notifications Logs
function CarbonBlackAPI()
{
    $workspaceId = $env:workspaceId
    $workspaceSharedKey = $env:workspaceKey
    $hostName = $env:uri
    $apiSecretKey = $env:apiKey
    $apiId = $env:apiId
    $SIEMapiKey = $env:SIEMapiKey
    $SIEMapiId = $env:SIEMapiId
    $time = $env:timeInterval
    $AuditLogTable = "CarbonBlackAuditLogsTest"
    $EventLogTable = "CarbonBlackEventsTest"
    $NotificationTable  = "CarbonBlackNotificationsTest"
    $OrgKey = $env:CarbonBlackOrgKey
    $s3BucketName = $env:s3BucketName
    #$prefixFolder = $env:s3BucketPrefixFolder
    $EventprefixFolder = "carbon-black-events"
    $AlertprefixFolder = "carbon-black-alerts"
    $AWSAccessKeyId = $env:AWSAccessKeyId
    $AWSSecretAccessKey = $env:AWSSecretAccessKey

    $startTime = [System.DateTime]::UtcNow.AddMinutes(-$($time))
    $now = [System.DateTime]::UtcNow

    # Remove if addition slash or space added in hostName
    $hostName = $hostName.Trim() -replace "[.*/]$",""

    if ([string]::IsNullOrEmpty($logAnalyticsUri))
    {
        $logAnalyticsUri = "https://" + $workspaceId + ".ods.opinsights.azure.com"
    }
    
    # Returning if the Log Analytics Uri is in incorrect format.
    # Sample format supported: https://" + $customerId + ".ods.opinsights.azure.com
    if($logAnalyticsUri -notmatch 'https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$')
    {
        throw "VMware Carbon Black: Invalid Log Analytics Uri."
    }    

    $authHeaders = @{
        "X-Auth-Token" = "$($apiSecretKey)/$($apiId)"
    }

    $auditLogsResult = Invoke-RestMethod -Headers $authHeaders -Uri ([System.Uri]::new("$($hostName)/integrationServices/v3/auditlogs"))
    
    if ($auditLogsResult.success -eq $true)
    {
        $AuditLogsJSON = $auditLogsResult.notifications | ConvertTo-Json -Depth 5
        if (-not([string]::IsNullOrWhiteSpace($AuditLogsJSON)))
        {
            $responseObj = (ConvertFrom-Json $AuditLogsJSON)
            $status = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($AuditLogsJSON)) -logType $AuditLogTable;
            Write-Host("$($responseObj.count) new Carbon Black Audit Events as of $([DateTime]::UtcNow). Pushed data to Azure sentinel Status code:$($status)")
        }
        else
        {
            Write-Host "No new Carbon Black Audit Events as of $([DateTime]::UtcNow)"
        }
    }
    else
    {
        Write-Host "AuditLogsResult API status failed , Please check."
    }

    GetBucketDetails -s3BucketName $s3BucketName -prefixFolder $EventprefixFolder -tableName $EventLogTable

    # IF ($Null -ne $s3BucketName) {
    #     Set-AWSCredentials -AccessKey $AWSAccessKeyId -SecretKey $AWSSecretAccessKey

    #     while ($startTime -le $now) {
    #         $keyPrefix = "$prefixFolder/org_key=$OrgKey/year=$($startTime.Year)/month=$($startTime.Month)/day=$($startTime.Day)/hour=$($startTime.Hour)/minute=$($startTime.Minute)"
    #         Get-S3Object -BucketName $s3BucketName -keyPrefix $keyPrefix | Read-S3Object -Folder "/tmp"
    #         Write-Host "Files under $keyPrefix are downloaded."
    
    #         if (Test-Path -Path "/tmp/$keyPrefix") {
    #             Get-ChildItem -Path "/tmp" -Recurse -Include *.gz | 
    #             Foreach-Object {
    #                 $filename = $_.FullName
    #                 $infile = $_.FullName				
    #                 $outfile = $_.FullName -replace ($_.Extension, '')
    #                 Expand-GZipFile $infile.Trim() $outfile.Trim()
    #                 $null = Remove-Item -Path $infile -Force -Recurse -ErrorAction Ignore
    #                 $filename = $filename -replace ($_.Extension, '')
    #                 $filename = $filename.Trim()
                
    #                 $logEvents = Get-Content -Raw -LiteralPath ($filename) 
    #                 $logevents = ConvertFrom-Json $LogEvents -AsHashTable
    #                 EventsFieldsMapping -events $logEvents
    #                 $EventLogsJSON = $logEvents | ConvertTo-Json -Depth 5
    
    #                 if (-not([string]::IsNullOrWhiteSpace($EventLogsJSON)))
    #                 {
    #                     $responseObj = (ConvertFrom-Json $EventLogsJSON)
    #                     $status = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($EventLogsJSON)) -logType $EventLogTable;
    #                     Write-Host("$($responseObj.count) new Carbon Black Events as of $([DateTime]::UtcNow). Pushed data to Azure sentinel Status code:$($status)")
    #                 }
    
    #                 $null = Remove-Variable -Name LogEvents
    #             }
    
    #             Remove-Item -LiteralPath "/tmp/$keyPrefix" -Force -Recurse
    #         }
    
    #         $startTime = $startTime.AddMinutes(1)
    #     }
    # }

    if($SIEMapiKey -eq '<Optional>' -or  $SIEMapiId -eq '<Optional>'  -or [string]::IsNullOrWhitespace($SIEMapiKey) -or  [string]::IsNullOrWhitespace($SIEMapiId))
    {   
        GetBucketDetails -s3BucketName $s3BucketName -prefixFolder $AlertprefixFolder -tableName $NotificationTable
         Write-Host "No SIEM API ID and/or Key value was defined."   
    }
    else
    {                
        $authHeaders = @{"X-Auth-Token" = "$($SIEMapiKey)/$($SIEMapiId)"}
        $notifications = Invoke-RestMethod -Headers $authHeaders -Uri ([System.Uri]::new("$($hostName)/integrationServices/v3/notification"))
        if ($notifications.success -eq $true)
        {                
            $NotifLogJson = $notifications.notifications | ConvertTo-Json -Depth 5       
            if (-not([string]::IsNullOrWhiteSpace($NotifLogJson)))
            {
                $responseObj = (ConvertFrom-Json $NotifLogJson)
                $status = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($NotifLogJson)) -logType $NotificationTable;
                Write-Host("$($responseObj.count) new Carbon Black Notifications as of $([DateTime]::UtcNow). Pushed data to Azure sentinel Status code:$($status)")
            }
            else
            {
                    Write-Host "No new Carbon Black Notifications as of $([DateTime]::UtcNow)"
            }
        }
        else
        {
            Write-Host "Notifications API status failed , Please check."
        }
    }    
}

# Create the function to create the authorization signature
function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date;
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource;
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash);
    $keyBytes = [Convert]::FromBase64String($sharedKey);
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256;
    $sha256.Key = $keyBytes;
    $calculatedHash = $sha256.ComputeHash($bytesToHash);
    $encodedHash = [Convert]::ToBase64String($calculatedHash);
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash;
    return $authorization;
}

# Create the function to create and post the request
function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $TimeStampField = "eventTime"
    $method = "POST";
    $contentType = "application/json";
    $resource = "/api/logs";
    $rfc1123date = [DateTime]::UtcNow.ToString("r");
    $contentLength = $body.Length;
    $signature = Build-Signature -customerId $customerId -sharedKey $sharedKey -date $rfc1123date -contentLength $contentLength -method $method -contentType $contentType -resource $resource;
    $logAnalyticsUri = $logAnalyticsUri + $resource + "?api-version=2016-04-01"
    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    };
    $response = Invoke-WebRequest -Body $body -Uri $logAnalyticsUri -Method $method -ContentType $contentType -Headers $headers -UseBasicParsing
    return $response.StatusCode
}

function GetBucketDetails {
    param (
        $s3BucketName,
        $prefixFolder,
        $tableName
    )

    IF ($Null -ne $s3BucketName) {
        Set-AWSCredentials -AccessKey $AWSAccessKeyId -SecretKey $AWSSecretAccessKey

        while ($startTime -le $now) {
            $keyPrefix = "$prefixFolder/org_key=$OrgKey/year=$($startTime.Year)/month=$($startTime.Month)/day=$($startTime.Day)/hour=$($startTime.Hour)/minute=$($startTime.Minute)"
            Get-S3Object -BucketName $s3BucketName -keyPrefix $keyPrefix | Read-S3Object -Folder "C:\tmp"
            Write-Host "Files under $keyPrefix are downloaded."
    
            if (Test-Path -Path "/tmp/$keyPrefix") {
                Get-ChildItem -Path "/tmp" -Recurse -Include *.gz | 
                Foreach-Object {
                    $filename = $_.FullName
                    $infile = $_.FullName				
                    $outfile = $_.FullName -replace ($_.Extension, '')
                    Expand-GZipFile $infile.Trim() $outfile.Trim()
                    $null = Remove-Item -Path $infile -Force -Recurse -ErrorAction Ignore
                    $filename = $filename -replace ($_.Extension, '')
                    $filename = $filename.Trim()
                    $AllEvents = [System.Collections.ArrayList]::new()

                    foreach ($logEvent in [System.IO.File]::ReadLines($filename))
                    {
                        $logevents = ConvertFrom-Json $logEvent -AsHashTable
                        if($prefixFolder -eq "carbon-black-events")
                        {
                            EventsFieldsMapping -events $logevents
                        }
                        if($prefixFolder -eq "carbon-black-alerts")
                        {
                            AlertsFieldsMapping -alerts $logevents
                        }
                        $AllEvents.Add($logevents)
                    }

                    $EventLogsJSON = $AllEvents | ConvertTo-Json -Depth 5
    
                    if (-not([string]::IsNullOrWhiteSpace($EventLogsJSON)))
                    {
                        $responseObj = (ConvertFrom-Json $EventLogsJSON)
                        try {
                            $status = Post-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($EventLogsJSON)) -logType $tableName;  
                        }
                        catch {
                            Write-Host $_
                        }
                        Write-Host("$($responseObj.count) new Carbon Black Events as of $([DateTime]::UtcNow). Pushed data to Azure sentinel Status code:$($status)")
                    }
                    $null = Remove-Variable -Name AllEvents
                }
    
                Remove-Item -LiteralPath "/tmp/$keyPrefix" -Force -Recurse
            }
    
            $startTime = $startTime.AddMinutes(1)
        }
    }
}

# Execute the Function to Pull CarbonBlack data and Post to the Log Analytics Workspace
CarbonBlackAPI

# Write an information log with the current time.
Write-Host "PowerShell timer trigger function ran! TIME: $currentUTCtime"
