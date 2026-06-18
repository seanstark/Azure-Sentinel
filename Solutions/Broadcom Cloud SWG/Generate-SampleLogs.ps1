# Generates sample Broadcom Cloud SWG logs in the raw Extended Log File Format (ELFF)
# field names that the appliance emits (e.g. c-ip, cs-bytes, x-bluecoat-access-type).
# The data connector's DCR stream declaration consumes these raw names and renames them
# to the BroadcomCloudSWG_CL schema columns via transformKql.
# Output: gzip-compressed JSON array files ready to upload to a storage account blob container.

$ErrorActionPreference = 'Stop'

$outDir = Join-Path $PSScriptRoot 'SampleLogs'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# Value pools for realistic sample data
$actions        = @('ALLOWED', 'DENIED', 'FAILED', 'SERVER_ERROR', 'ISOLATION_CS', 'ISOLATION_INITIATED', 'ISOLATED_DOCUMENT')
$actionResults  = @('ALLOWED', 'FAILED', 'DENIED', 'UNKNOWN')
$verdicts       = @('Allowed', 'Denied')
$methods        = @('GET', 'POST', 'PUT', 'DELETE', 'CONNECT', 'HEAD')
$schemes        = @('https', 'http')
$ipVersions     = @('IPv4', 'IPv6')
$categories     = @('Technology/Internet', 'Search Engines/Portals', 'Business/Economy', 'Social Networking', 'Computers/Internet', 'News/Media', 'Suspicious', 'Malicious Sources/Malnets')
$riskLevels     = @('1', '2', '3', '4', '5', '6', '7', '8', '9', '10')
$riskGroups     = @('Trustworthy', 'Low Risk', 'Medium Risk', 'High Risk', 'Suspicious/Malicious')
$tlsVersions    = @('TLSv1.2', 'TLSv1.3')
$tlsCiphers     = @('TLS_AES_256_GCM_SHA384', 'ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES128-GCM-SHA256')
$cipherStrength = @('High', 'Medium', 'Low')
$countries      = @('United States', 'United Kingdom', 'Germany', 'Australia', 'Japan', 'Canada', 'France', 'India')
$countryCodes   = @('US', 'GB', 'DE', 'AU', 'JP', 'CA', 'FR', 'IN')
$regions        = @('NSW', 'CA', 'VA', 'TX', 'LON', 'FRA', 'TYO')
$osList         = @('Windows 10', 'Windows 11', 'macOS 14', 'iOS 17', 'Android 14', 'Ubuntu 22.04')
$deviceTypes    = @('Desktop', 'Laptop', 'Mobile', 'Tablet')
$agentTypes     = @('WSS Agent', 'SEP', 'Unified Agent', 'Browser')
$hosts          = @('www.example.com', 'login.microsoftonline.com', 'cdn.contoso.com', 'mail.google.com', 'github.com', 'malware-test.bad', 'updates.symantec.com')
$webApps        = @('Microsoft Office 365', 'Salesforce', 'Dropbox', 'YouTube', 'Facebook', 'Box', 'ServiceNow')
$appOps         = @('Upload', 'Download', 'Login', 'Share', 'Post', 'Delete')
$uploadSources  = @('datapath', 'hosted')
$accessTypes    = @('Direct', 'Proxy Forwarding', 'Explicit Proxy', 'IPSEC')
$inspected      = @('INSPECTED', 'NOT_INSPECTED')
$requestOrigins = @('client', 'isolation')
$sbVerdicts     = @('CLEAN', 'SUSPICIOUS', 'MALWARE')
$filterResults  = @('DENIED', 'PROXIED', 'OBSERVED')
$tunnelProtos   = @('TCP', 'UDP', 'proxy')
$dnsOpcodes     = @('QUERY', 'IQUERY', 'STATUS')
$dnsQTypes      = @('A', 'AAAA', 'CNAME', 'MX', 'PTR', 'TXT', 'NS')
$dnsQClasses    = @('IN', 'CH', 'HS')
$dnsRCodes      = @('NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED')
$dnsTransports  = @('UDP', 'TCP', 'DoH', 'DoT')
$statusCodes    = @(200, 200, 200, 204, 301, 302, 304, 400, 403, 404, 407, 500, 502, 503)
$fileTypes      = @('pdf', 'docx', 'xlsx', 'zip', 'exe', 'png', 'jpg', 'js', 'html')
$mimeTypes      = @('application/pdf', 'application/octet-stream', 'text/html', 'image/png', 'application/zip', 'application/javascript')
$exceptionIds   = @('', '', '', 'authentication_failed', 'policy_denied', 'tcp_error', 'dns_unresolved_hostname')

function Get-RandomIP {
    "{0}.{1}.{2}.{3}" -f (Get-Random -Min 1 -Max 223), (Get-Random -Max 256), (Get-Random -Max 256), (Get-Random -Min 1 -Max 255)
}
function Pick($arr) { $arr[(Get-Random -Max $arr.Count)] }
function Maybe($value, $emptyChance = 0.3) {
    if ((Get-Random -Minimum 0.0 -Maximum 1.0) -lt $emptyChance) { '-' } else { $value }
}
function Get-Hash($len) {
    -join ((1..$len) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) })
}

function New-LogRecord {
    param([datetime]$Timestamp)

    $host_   = Pick $hosts
    $scheme  = Pick $schemes
    $method  = Pick $methods
    $cc      = Pick ([int[]](0..($countries.Count - 1)))
    $isFile  = (Get-Random -Minimum 0.0 -Maximum 1.0) -lt 0.4
    $fileExt = Pick $fileTypes
    $action  = Pick $actions

    [ordered]@{
        TimeGenerated                        = $Timestamp.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        AccessType                           = Pick $accessTypes
        Action                               = $action
        ActionResult                         = Pick $actionResults
        ApplianceName                        = "edgeswg-{0:D2}" -f (Get-Random -Max 50)
        Application                          = Pick $webApps
        ApplicationGroup                     = Maybe (Pick @('Cloud Storage', 'Collaboration', 'Social Media', 'Productivity'))
        ApplicationOperation                 = Maybe (Pick $appOps)
        AuthGroup                            = Pick @('Domain Users', 'Sales', 'Engineering', 'Finance', 'IT-Admins')
        Categories                           = Pick $categories
        CertificateIssuer                    = Maybe (Pick @('DigiCert Inc', "Let's Encrypt", 'GlobalSign', 'Sectigo Limited'))
        ClientAgentIP                        = Maybe (Get-RandomIP)
        ClientAgentSW                        = Maybe ("8.{0}.{1}.{2}" -f (Get-Random -Max 10), (Get-Random -Max 20), (Get-Random -Max 1000))
        ClientAgentType                      = Pick $agentTypes
        ClientBytes                          = Get-Random -Min 100 -Max 50000
        ClientCertificateSubject             = Maybe "CN=user$(Get-Random -Max 999),OU=Users,DC=corp,DC=local"
        ClientDeviceID                       = (New-Guid).ToString()
        ClientDeviceName                     = "DESKTOP-{0}" -f (Get-Hash 6).ToUpper()
        ClientDeviceType                     = Pick $deviceTypes
        ClientIP                             = Get-RandomIP
        ClientIPCountry                      = $countries[$cc]
        ClientIPSubnet                       = "{0}.0/24" -f ((Get-RandomIP) -replace '\.\d+$', '')
        ClientIPVersion                      = Pick $ipVersions
        ClientOCSPError                      = Maybe '-' 0.85
        ClientOS                             = Pick $osList
        ClientPort                           = Get-Random -Min 1024 -Max 65535
        ClientPublicIP                       = Get-RandomIP
        ClientTLSCipher                      = Pick $tlsCiphers
        ClientTLSCipherSize                  = Pick @(128, 256)
        ClientTLSVersion                     = Pick $tlsVersions
        ContentAction                        = Maybe (Pick @('Allow', 'Block', 'Isolate')) 0.6
        DataLeakDetected                     = Pick @('true', 'false')
        DatacenterName                       = Get-RandomIP
        Date                                 = $Timestamp.ToUniversalTime().ToString('yyyy-MM-dd')
        DEIApp                               = Maybe (Pick $webApps) 0.7
        DEIVia                               = Maybe (Get-Hash 12) 0.7
        Details                              = Maybe 'Event properties details' 0.6
        DestinationCountry                   = $countries[$cc]
        DestinationIP                        = Get-RandomIP
        DestinationIPVersion                 = Pick $ipVersions
        DisconnectReason                     = Maybe (Pick @('ShutDown', 'Reconnect', 'Disabled')) 0.7
        DLPAction                            = Pick @('Allow', 'Block', 'None')
        DLPResponseActionMessages            = Maybe 'Block by Corporate DLP policy' 0.7
        DLPViolations                        = Maybe "Policy Id: $(Get-Random -Max 999), Violation: web isolation profile" 0.7
        DNSLookupTime                        = Get-Random -Max 500
        DNSRequest                           = $host_
        DNSRequestCategory                   = Pick $categories
        DNSRequestOpcode                     = Pick $dnsOpcodes
        DNSRequestQClass                     = Pick $dnsQClasses
        DNSRequestQType                      = Pick $dnsQTypes
        DNSRequestThreatRiskLevel            = Pick $riskLevels
        DNSRequestTransport                  = Pick $dnsTransports
        DNSResponseARecords                  = "$(Get-RandomIP),$(Get-RandomIP)"
        DNSResponseCNAMERecords              = Maybe "cdn.$host_" 0.5
        DNSResponsePTRRecords                = Maybe "ptr.$host_" 0.6
        DNSResponseRCode                     = Pick $dnsRCodes
        DNSReverseLookupAddress              = Maybe (Get-RandomIP) 0.6
        DocIsolationProfile                  = Maybe "profile-$(Get-Random -Max 99)" 0.6
        DownloadID                           = Maybe (New-Guid).ToString() 0.6
        DPICategoriesOfInterest              = Maybe 'Web' 0.5
        DPICategory                          = Maybe 'Web' 0.4
        DPIClassification                    = Maybe 'tcp.ssl.https.office365' 0.4
        DPIClassificationsOfInterest         = Maybe 'tcp.ssl.https' 0.5
        DPIFirstPacketCategory               = Maybe 'Web' 0.5
        DPIFirstPacketClassification         = Maybe 'tcp.ssl' 0.5
        DriveByAction                        = Maybe (Pick @('Allow', 'Block')) 0.7
        EgressIP                             = Get-RandomIP
        ErrorType                            = Maybe (Pick @('TimeoutError', 'ConnectionReset', 'CertError')) 0.7
        ExceptionID                          = Pick $exceptionIds
        ExtraLogData                         = Maybe 'client-generated-data' 0.7
        FileName                             = if ($isFile) { "document-$(Get-Random -Max 9999).$fileExt" } else { '-' }
        FileReputationScore                  = Maybe ("{0}" -f (Get-Random -Max 11)) 0.5
        FileSizeDownloadBytes                = if ($isFile) { Get-Random -Min 1024 -Max 10485760 } else { 0 }
        FileSizeUploadBytes                  = if ($isFile) { Get-Random -Max 1048576 } else { 0 }
        FileType                             = if ($isFile) { $fileExt } else { '-' }
        FilterResult                         = Pick $filterResults
        FirewallBytes                        = Get-Random -Max 100000
        FirewallPackets                      = Get-Random -Max 1000
        FirewallPort                         = Pick @(53, 80, 443, 8080)
        FirstByteLatency                     = Get-Random -Max 2000
        HTTPConnectHost                      = if ($method -eq 'CONNECT') { $host_ } else { '-' }
        HTTPConnectPort                      = if ($method -eq 'CONNECT') { 443 } else { 0 }
        HTTPMimeType                         = Pick $mimeTypes
        ICAPReqmodErrorDetails               = Maybe '-' 0.85
        ICAPReqmodMetadata                   = Maybe 'reqmod-metadata' 0.7
        ICAPRequestService                   = Maybe 'DLP-REQMOD' 0.5
        ICAPRequestStatus                    = Maybe (Pick @('200', '204')) 0.5
        ICAPRespmodFileDetails               = Maybe "$fileExt,application" 0.6
        ICAPRespmodMetadata                  = Maybe 'respmod-metadata' 0.7
        ICAPRespmodResolvedDataTypes         = if ($isFile) { $fileExt } else { '-' }
        ICAPResponseService                  = Maybe 'AV-RESPMOD' 0.5
        ICAPResponseStatus                   = Maybe (Pick @('200', '204')) 0.5
        ImageData                            = Pick @('true', 'false')
        Inspected                            = Pick $inspected
        IsolationURL                         = Maybe "https://isolation.threatpulse.net/$(Get-Hash 16)" 0.7
        LocationName                         = "Branch-$(Pick $countryCodes)-$(Get-Random -Max 50)"
        MADetonated                          = Pick @(0, 1)
        MASandboxVerdict                     = Maybe (Pick $sbVerdicts) 0.6
        MD5                                  = if ($isFile) { Get-Hash 32 } else { '-' }
        Method                               = $method
        MimeType                             = Pick $mimeTypes
        PageViews                            = Pick @(0, 1)
        PasswordSupplied                     = Pick @('true', 'false')
        PhishingAction                       = Maybe (Pick @('Allow', 'Block')) 0.8
        PhishingType                         = Maybe (Pick @('Credential', 'Deceptive')) 0.8
        Placeholder                          = '-'
        PodDetails                           = "pod-$(Pick $regions)-$(Get-Random -Max 20)"
        ReadOnlyAction                       = Maybe (Pick @('Allow', 'Block')) 0.8
        Reason                               = Maybe 'Policy match' 0.6
        Referer                              = Maybe "https://$(Pick $hosts)/" 0.4
        RefererURICategories                 = Maybe (Pick $categories) 0.5
        ReferenceID                          = Maybe ("TP-G{0}" -f (Get-Random -Max 20)) 0.4
        ReferenceIDs                         = Maybe ("TP-G{0};AUTH-1" -f (Get-Random -Max 20)) 0.5
        Region                               = Pick $regions
        RequestHTTPVersion                   = Pick @('HTTP/1.1', 'HTTP/2')
        RequestOrigin                        = Pick $requestOrigins
        ResourceType                         = Maybe (Pick @('document', 'script', 'image', 'stylesheet')) 0.5
        ResponseCached                       = Pick @('true', 'false')
        ResponseContentType                  = Pick $mimeTypes
        ResponseHTTPVersion                  = Pick @('HTTP/1.1', 'HTTP/2')
        RiskGroups                           = Pick $riskGroups
        SearchTerms                          = Maybe 'quarterly report' 0.7
        ServerBytes                          = Get-Random -Min 100 -Max 5000000
        ServerCertificateHostname            = $host_
        ServerCertificateHostnameCategories  = Pick $categories
        ServerCertificateHostnameCategory    = Pick $categories
        ServerCertificateHostnameThreatRisk  = Pick $riskLevels
        ServerCertificateObservedErrors      = Maybe '-' 0.85
        ServerCertificateValidateStatus      = Pick @('OK', 'EXPIRED', 'UNTRUSTED_ISSUER')
        ServerComputerName                   = "proxy-$(Pick $regions)-$(Get-Random -Max 50)"
        ServerHierarchy                      = Pick @('DIRECT', 'PARENT', 'NONE')
        ServerIP                             = Get-RandomIP
        ServerOCSPError                      = Maybe '-' 0.85
        ServerSourceIP                       = Get-RandomIP
        ServerTLSCipher                      = Pick $tlsCiphers
        ServerTLSCipherSize                  = Pick @(128, 256)
        ServerTLSCipherStrength              = Pick $cipherStrength
        ServerTLSVersion                     = Pick $tlsVersions
        SHA1                                 = if ($isFile) { Get-Hash 40 } else { '-' }
        SHA256                               = if ($isFile) { Get-Hash 64 } else { '-' }
        StatusCode                           = Pick $statusCodes
        Tags                                 = Maybe 'isolation,monitored' 0.6
        TenantID                             = (New-Guid).ToString()
        ThreatRisk                           = Pick $riskLevels
        Time                                 = $Timestamp.ToUniversalTime().ToString('HH:mm:ss')
        TimeTaken                            = Get-Random -Max 10000
        TimestampUnix                        = [int64](([datetimeoffset]$Timestamp).ToUnixTimeSeconds())
        TransactionUUID                      = (New-Guid).ToString()
        TunnelPort                           = Pick @(443, 8080, 80)
        TunnelProtocol                       = Pick $tunnelProtos
        TunnelUser                           = "user$(Get-Random -Max 999)@corp.local"
        UIUser                               = Maybe "admin$(Get-Random -Max 99)" 0.7
        UploadSource                         = Pick $uploadSources
        UriExtension                         = if ($isFile) { $fileExt } else { '-' }
        UriPath                              = "/path/$(Get-Hash 4)/resource"
        UriPort                              = if ($scheme -eq 'https') { 443 } else { 80 }
        UriQuery                             = Maybe "id=$(Get-Random -Max 9999)&ref=email" 0.4
        UriScheme                            = $scheme
        UserAgent                            = Pick @('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36', 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)', 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)')
        UserDN                               = "user$(Get-Random -Max 999)@corp.local"
        UserDomain                           = 'corp.local'
        Verdict                              = Pick $verdicts
        VirusID                              = Maybe (Pick @('Trojan.Gen.2', 'W32.Downadup', 'EICAR-Test-File')) 0.85
        VPopCountry                          = $countries[$cc]
        VPopCountryCode                      = $countryCodes[$cc]
        WebApplication                       = Pick $webApps
        XFileName                            = if ($isFile) { "document-$(Get-Random -Max 9999).$fileExt" } else { '-' }
        XFileSHA256                          = if ($isFile) { Get-Hash 64 } else { '-' }
        XFileSize                            = if ($isFile) { Get-Random -Min 1024 -Max 10485760 } else { 0 }
        XForwardedFor                        = "$(Get-RandomIP), $(Get-RandomIP)"
        XRequestedWith                       = Maybe 'XMLHttpRequest' 0.5
    }
}

function Write-GzipJson {
    param([string]$Path, [object]$Object)

    $json  = $Object | ConvertTo-Json -Depth 5 -Compress
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)

    $fs   = [System.IO.File]::Create($Path)
    try {
        $gz = New-Object System.IO.Compression.GzipStream($fs, [System.IO.Compression.CompressionMode]::Compress)
        try { $gz.Write($bytes, 0, $bytes.Length) }
        finally { $gz.Dispose() }
    }
    finally { $fs.Dispose() }
}

# Maps the friendly schema column name (produced by New-LogRecord) to the raw
# Broadcom Cloud SWG Extended Log File Format (ELFF) field name that the appliance
# actually emits. The data connector's DCR stream declaration expects these raw
# names and renames them to the friendly columns via transformKql.
$friendlyToElff = [ordered]@{
    AccessType                           = 'x-bluecoat-access-type'
    Action                               = 's-action'
    ActionResult                         = 'action-result'
    ApplianceName                        = 'x-bluecoat-appliance-name'
    Application                          = 'application-name'
    ApplicationGroup                     = 'x-bluecoat-application-group'
    ApplicationOperation                 = 'x-bluecoat-application-operation'
    AuthGroup                            = 'cs-auth-group'
    Categories                           = 'cs-categories'
    CertificateIssuer                    = 'issuer'
    ClientAgentIP                        = 'x-client-agent-ip'
    ClientAgentSW                        = 'x-client-agent-sw'
    ClientAgentType                      = 'x-client-agent-type'
    ClientBytes                          = 'cs-bytes'
    ClientCertificateSubject             = 'x-cs-certificate-subject'
    ClientDeviceID                       = 'x-client-device-id'
    ClientDeviceName                     = 'x-client-device-name'
    ClientDeviceType                     = 'x-client-device-type'
    ClientIP                             = 'c-ip'
    ClientIPCountry                      = 'x-cs-client-ip-country'
    ClientIPSubnet                       = 'c-ip-subnet'
    ClientIPVersion                      = 'c-ip-version'
    ClientOCSPError                      = 'x-cs-ocsp-error'
    ClientOS                             = 'x-client-os'
    ClientPort                           = 'c-port'
    ClientPublicIP                       = 'x-cs-public-ip'
    ClientTLSCipher                      = 'x-cs-connection-negotiated-cipher'
    ClientTLSCipherSize                  = 'x-cs-connection-negotiated-cipher-size'
    ClientTLSVersion                     = 'x-cs-connection-negotiated-ssl-version'
    ContentAction                        = 'content-action'
    DataLeakDetected                     = 'x-data-leak-detected'
    DatacenterName                       = 'datacenter-name'
    Date                                 = 'date'
    DEIApp                               = 'x-symc-dei-app'
    DEIVia                               = 'x-symc-dei-via'
    Details                              = 'details'
    DestinationCountry                   = 'r-supplier-country'
    DestinationIP                        = 'r-ip'
    DestinationIPVersion                 = 'r-ip-version'
    DisconnectReason                     = 'disconnect-reason'
    DLPAction                            = 'dlp-action'
    DLPResponseActionMessages            = 'dlp-response-action-messages'
    DLPViolations                        = 'dlp-violations'
    DNSLookupTime                        = 'x-dns-lookup-time'
    DNSRequest                           = 'x-dns-cs-dns'
    DNSRequestCategory                   = 'x-dns-cs-category'
    DNSRequestOpcode                     = 'x-dns-cs-opcode'
    DNSRequestQClass                     = 'x-dns-cs-qclass'
    DNSRequestQType                      = 'x-dns-cs-qtype'
    DNSRequestThreatRiskLevel            = 'x-dns-cs-threat-risk-level'
    DNSRequestTransport                  = 'x-dns-cs-transport'
    DNSResponseARecords                  = 'x-dns-rs-a-records'
    DNSResponseCNAMERecords              = 'x-dns-rs-cname-records'
    DNSResponsePTRRecords                = 'x-dns-rs-ptr-records'
    DNSResponseRCode                     = 'x-dns-rs-rcode'
    DNSReverseLookupAddress              = 'x-dns-cs-address'
    DocIsolationProfile                  = 'doc-isolation-profile'
    DownloadID                           = 'download-id'
    DPICategoriesOfInterest              = 'x-variable(dpi_categories_of_interest)'
    DPICategory                          = 'x-dpi-category'
    DPIClassification                    = 'x-dpi-classification'
    DPIClassificationsOfInterest         = 'x-variable(dpi_classification_of_interest)'
    DPIFirstPacketCategory               = 'x-dpi-first-packet-category'
    DPIFirstPacketClassification         = 'x-dpi-first-packet-classification'
    DriveByAction                        = 'drive-by-action'
    EgressIP                             = 'x-sr-vpop-ip'
    ErrorType                            = 'error-type'
    ExceptionID                          = 'x-exception-id'
    ExtraLogData                         = 'extra-log-data'
    FileName                             = 'file-name'
    FileReputationScore                  = 'x-symc-file-reputation-score'
    FileSizeDownloadBytes                = 'file-size-download-bytes'
    FileSizeUploadBytes                  = 'file-size-upload-bytes'
    FileType                             = 'file-type'
    FilterResult                         = 'sc-filter-result'
    FirewallBytes                        = 'cs-firewall-bytes'
    FirewallPackets                      = 'cs-firewall-pkts'
    FirewallPort                         = 'cs-firewall-port'
    FirstByteLatency                     = 'x-bluecoat-first-byte-latency'
    HTTPConnectHost                      = 'x-http-connect-host'
    HTTPConnectPort                      = 'x-http-connect-port'
    HTTPMimeType                         = 'http-mime-type'
    ICAPReqmodErrorDetails               = 'cs-icap-error-details'
    ICAPReqmodMetadata                   = 'x-icap-reqmod-header(x-icap-metadata)'
    ICAPRequestService                   = 'cs-icap-service'
    ICAPRequestStatus                    = 'cs-icap-status'
    ICAPRespmodFileDetails               = 'x-icap-respmod-header(x-file-details)'
    ICAPRespmodMetadata                  = 'x-icap-respmod-header(x-icap-metadata)'
    ICAPRespmodResolvedDataTypes         = 'x-icap-respmod-resolved-data-types'
    ICAPResponseService                  = 'rs-icap-service'
    ICAPResponseStatus                   = 'rs-icap-status'
    ImageData                            = 'image-data'
    Inspected                            = 'x-symc-inspected'
    IsolationURL                         = 'isolation-url'
    LocationName                         = 'x-bluecoat-location-name'
    MADetonated                          = 'ma-detonated'
    MASandboxVerdict                     = 'ma-sb-verdict'
    MD5                                  = 'md5'
    Method                               = 'cs-method'
    MimeType                             = 'mime-type'
    PageViews                            = 'page-views'
    PasswordSupplied                     = 'password-supplied'
    PhishingAction                       = 'phishing-action'
    PhishingType                         = 'phishing-type'
    Placeholder                          = 'x-bluecoat-placeholder'
    PodDetails                           = 'pod-details'
    ReadOnlyAction                       = 'read-only-action'
    Reason                               = 'reason'
    Referer                              = 'cs(referer)'
    RefererURICategories                 = 'x-cs(referer)-uri-categories'
    ReferenceID                          = 'x-bluecoat-reference-id'
    ReferenceIDs                         = 'x-bluecoat-reference-ids'
    Region                               = 'gcp-region'
    RequestHTTPVersion                   = 'cs-version'
    RequestOrigin                        = 'x-request-origin'
    ResourceType                         = 'resource-type'
    ResponseCached                       = 'response-cached'
    ResponseContentType                  = 'rs(content-type)'
    ResponseHTTPVersion                  = 'rs-version'
    RiskGroups                           = 'risk-groups'
    SearchTerms                          = 'search-terms'
    ServerBytes                          = 'sc-bytes'
    ServerCertificateHostname            = 'x-rs-certificate-hostname'
    ServerCertificateHostnameCategories  = 'x-rs-certificate-hostname-categories'
    ServerCertificateHostnameCategory    = 'x-rs-certificate-hostname-category'
    ServerCertificateHostnameThreatRisk  = 'x-rs-certificate-hostname-threat-risk'
    ServerCertificateObservedErrors      = 'x-rs-certificate-observed-errors'
    ServerCertificateValidateStatus      = 'x-rs-certificate-validate-status'
    ServerComputerName                   = 's-computername'
    ServerHierarchy                      = 's-hierarchy'
    ServerIP                             = 's-ip'
    ServerOCSPError                      = 'x-rs-ocsp-error'
    ServerSourceIP                       = 's-source-ip'
    ServerTLSCipher                      = 'x-rs-connection-negotiated-cipher'
    ServerTLSCipherSize                  = 'x-rs-connection-negotiated-cipher-size'
    ServerTLSCipherStrength              = 'x-rs-connection-negotiated-cipher-strength'
    ServerTLSVersion                     = 'x-rs-connection-negotiated-ssl-version'
    SHA1                                 = 'sha1'
    SHA256                               = 'sha256'
    StatusCode                           = 'sc-status'
    Tags                                 = 'tags'
    TenantID                             = 'x-tenant-id'
    ThreatRisk                           = 'cs-threat-risk'
    Time                                 = 'time'
    TimeTaken                            = 'time-taken'
    TimestampUnix                        = 'x-timestamp-unix'
    TransactionUUID                      = 'x-bluecoat-transaction-uuid'
    TunnelPort                           = 'tunnel-port'
    TunnelProtocol                       = 'tunnel-protocol'
    TunnelUser                           = 'tunnel-user'
    UIUser                               = 'ui-user'
    UploadSource                         = 'upload-source'
    UriExtension                         = 'cs-uri-extension'
    UriPath                              = 'cs-uri-path'
    UriPort                              = 'cs-uri-port'
    UriQuery                             = 'cs-uri-query'
    UriScheme                            = 'cs-uri-scheme'
    UserAgent                            = 'cs(user-agent)'
    UserDN                               = 'cs-userdn'
    UserDomain                           = 'cs-user-domain'
    Verdict                              = 'verdict'
    VirusID                              = 'x-virus-id'
    VPopCountry                          = 'x-sr-vpop-country'
    VPopCountryCode                      = 'x-sr-vpop-country-code'
    WebApplication                       = 'x-bluecoat-application-name'
    XFileName                            = 'x-file-name'
    XFileSHA256                          = 'x-file-sha256'
    XFileSize                            = 'x-file-size'
    XForwardedFor                        = 'cs(X-Forwarded-For)'
    XRequestedWith                       = 'cs(x-requested-with)'
}

# Converts a friendly record (from New-LogRecord) into a raw ELFF record keyed by
# the field names the appliance emits. The TimeGenerated helper column is dropped
# because the DCR derives it from the date + time fields.
function ConvertTo-ElffRecord {
    param([System.Collections.Specialized.OrderedDictionary]$Record)

    $raw = [ordered]@{}
    foreach ($entry in $friendlyToElff.GetEnumerator()) {
        $raw[$entry.Value] = $Record[$entry.Key]
    }
    $raw
}

# Generate N files, each containing a JSON array of raw ELFF records timestamped at "now"
$fileCount       = 3
$recordsPerFile  = 50
$baseTime        = (Get-Date).ToUniversalTime()

for ($f = 1; $f -le $fileCount; $f++) {
    $records = for ($i = 0; $i -lt $recordsPerFile; $i++) {
        # Spread records across the last 5 minutes so TimeGenerated lands at "now"
        $ts = $baseTime.AddSeconds(-1 * (Get-Random -Max 300))
        ConvertTo-ElffRecord -Record (New-LogRecord -Timestamp $ts)
    }

    $stamp    = $baseTime.ToString('yyyyMMddHHmmss')
    $outFile  = Join-Path $outDir ("BroadcomCloudSWG_sample_{0}_{1:D2}.json.gz" -f $stamp, $f)
    Write-GzipJson -Path $outFile -Object @($records)
    Write-Host "Wrote $outFile ($recordsPerFile records)"
}

Write-Host "`nDone. Upload the *.json.gz files in '$outDir' to your blob container."
