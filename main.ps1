####################################
## Configuration
####################################
$logPath = "$PSScriptRoot\logs"
$logFileName = ((Get-Date -Format "yyyy-MM-dd hh.mm.sstt") + " - log.txt")
$daysToStoreLogs = 90 # any logs over this number will be automatically deleted

$nmapPath = "C:\Program Files (x86)\Nmap\nmap.exe" # nmap installed here. also be sure pcap is installed
$nmapTarget = "10.0.1.0/24" # use nmap cli syntax for target.

$ninjaBaseUrl = "https://app.ninjaone.com" # use your ninjaone custom url or just use app.ninjaone.com/
$ninjaClientId = "your_client_id" # your ninjaone api client id
$ninjaClientSecret = "your_secret_$Key!" # your ninjaone api secret
####################################
## [Functions]
####################################

## Function::logger - for logging to stdout and a file
function logger {
  param([string]$text)
  $timestamp = (Get-Date -Format "[yyyy.MM.dd hh:mm:sstt]")
  
  Write-Host -ForegroundColor Cyan -NoNewline $timestamp
  Write-Host " $($text)"

  "$timestamp $text" | Out-File -FilePath "$logPath\$logFileName" -Append
}

## Function::checkForRequirements - Check to make sure system meets requirements of the script
function checkForRequirements {
  # nmap
  logger("Checking for nmap...")
  $nmapFound = (Test-path $nmapPath)
  if (-not $nmapFound) {
    logger("ERROR: nmap was not found at the defined path ($nmapPath). Ensure nmap is installed and the nmapPath configured correctly.`r`n")
    exit 1
  }
}

## Function::nmapPingScan - Perform a ping scan using nmap to get ip addresses and mac addresses on the target network.
function nmapPingScan {
  param(
    [string]$target
    ,[string]$pathToXmlResults
  )

  if (Test-Path "$pathToXmlResults") {
    Remove-Item "$pathToXmlResults"
  }

  logger("Starting nmap scan...")
  $arguments = "-sn $target -oX `"$pathToXmlResults`""
  logger("Command: `"$nmapPath`" $arguments")

  $nmapProc = New-Object System.Diagnostics.ProcessStartInfo
  $nmapProc.FileName = "$nmapPath"
  $nmapProc.RedirectStandardError = $true
  $nmapProc.UseShellExecute = $false
  $nmapProc.Arguments = "$arguments"
  $nmapProc.CreateNoWindow = $true

  $p = New-Object System.Diagnostics.Process
  $p.StartInfo = $nmapProc
  $p.Start() | out-null
  $p.WaitForExit()
  $err = $p.StandardError.ReadToEnd()
  
  if ($p.ExitCode -ne 0) {
    logger("ERROR: nmap exited with an error: $err")
    exit 1
  }
  
  logger("nmap scan has finished against $target")
  $scanResultsArray = getNmapPingScanResults -pathToXmlResults $pathToXmlResults

  return $scanResultsArray
}

## Function::getNmapPingScanResults - Reads the xml output of nmapPingScan and returns an array of objects containing the ip and mac mapping.
function getNmapPingScanResults {
  param(
    [string]$pathToXmlResults
  )

  $xmlNodes = Select-Xml -Path $pathToXmlResults -XPath "/nmaprun/host"
  $hostNodes = @()
  foreach ($hostnode in $xmlNodes.node) {
    $ipv4 = ($hostnode.address | Where-Object -property addrtype -eq ipv4).addr
    $mac  = ($hostnode.address | Where-Object -property addrtype -eq mac).addr
    $hostname = ($hostnode.hostnames.hostname | Where-Object -property type -eq ptr).name
  
    $global:node = $hostnode
    $result = [pscustomobject]@{
      ipv4 = $ipv4
      mac = $mac
      hostname = $hostname
    }
    $hostNodes += $result
  }
  return $hostNodes
}

function logException {
  param(
    [string]$Message,
    $ExceptionObj
  )
  
  logger("ERROR: $Message
      ------
      $Exception
      ------")
}

## Function::getNinjaOAuthToken - Attempts to get an auth token from Ninja so it can connect to the api endpoints. Caches the result to prevent creating redundant tokens.
function getNinjaOAuthToken {
  logger("Attempting to login to NinjaOne...")
  
  # If one has already been cached
  if ($null -ne $global:ninjaAccessToken) {
    # If it is not past its expiration date
    if ((Get-Date) -lt $global:ninjaAccessToken.expires) {
      logger("Reusing cached access token.")
      return $global:ninjaAccessToken.access_token
    }
  }

  #No cached token, retrieve new one
  logger("Obtaining a new access token...")

  $apiPath = "/oauth/token"
  $params = "?grant_type=client_credentials"
  $params += "&client_id=$ninjaClientId"
  $params += "&client_secret=$ninjaClientSecret"
  $params += "&scope=monitoring"
  
  $response = Invoke-RestMethod -Method Post -Uri (-join($ninjaBaseUrl,$apiPath,$params))
  
  ## Ensure valid response 
  if ($null -ne $response -and $null -ne $response.access_token) {
    
    # Store it
    $global:ninjaAccessToken = [pscustomobject]@{
      # fields directly from the api response
      access_token = $response.access_token
      expires_in = $response.expires_in
      scope = $response.scope
      token_type = $response.token_type
      
      # calculated fields used by the script
      expires = ((Get-Date).AddSeconds($response.expires_in))
    }

    return $global:ninjaAccessToken.access_token
  }

  logger("ERROR: Unknown error while trying to retrieve Ninja OAuth token.")
  return $null
}

## Function::getNinjaDevices - Attempts to get all devices stored in Ninja by calling the Ninja API. Caches the result for a period of time to prevent sending too many calls.
function getNinjaDevices {
  param([bool]$skipCache=$false)

  # If device list has already been cached
  if ($null -ne $global:ninjaDevices -and $skipCache -eq $false) {

    # If the device list is not old/expired, reuse it
    if ((Get-Date) -lt $global:ninjaDevices.expires) {
        logger("Loading Ninja device list from cache.")
        return $global:ninjaDevices.deviceList
    }
  }

  logger("Obtaining new Ninja device list from the Ninja api...")
  $response = ninjaInvokeApi -apiEndpoint "/v2/devices-detailed" -retries 2

  ## Store the response if there is one
  if ($null -ne $response -and $null -ne $response[0].id) {
    $global:ninjaDevices = [pscustomobject]@{
      expires = (Get-Date).AddHours(1)
      deviceList = @($response)
    }
    logger("Detailed devices informaton retrieved.")
    return $global:ninjaDevices.deviceList
  }

  # No valid response object
  logger("ERROR: Unknown error while trying to retrieve Ninja devices.")
  return $null
}

## Function::ninjaInvokeApi - Sends a request to the Ninja api. If an error occurs, will retry the number of times specified.
function ninjaInvokeApi {
  param(
    [string]$apiEndpoint
    ,[int]$retries=1
  )

  $response = $null;

  ## Wrapper to retry in case of failure
  while ($null -eq $response -and $retries -gt 0)
  {
    # Need a token to access the api
    $oauthToken = getNinjaOAuthToken

    # No token could be obtained, return
    if ($null -eq $oauthToken) {
      logger("Unable to invoke $apiEndpoint because an access token could not be obtained.")
      return $null
    }
    
    # Call api
    try {
      logger("Invoking api request: $apiEndpoint")
      $headers = @{Authorization = "Bearer $oauthToken"}
      $response = Invoke-RestMethod -Method Get -Uri (-join($ninjaBaseUrl,$apiEndpoint)) -Headers $headers
    }
    catch {
      $exceptionObj = $_

      ## Error checking and recovery
      if ($null -ne $exceptionObj.ErrorDetails -and $null -ne $exceptionObj.ErrorDetails.Message) {
        $errorResponseFromNinja = ConvertFrom-Json $exceptionObj.ErrorDetails.Message
           
        ## Invalid Access Token - Remove the token and allow the script to pull a fresh one and try again
        if ($errorResponseFromNinja.error_description -eq "Invalid 'Authorization' header") {
            logger("Ninja doesn't like the current access token, attempting to retrieve a new one...")
            Remove-Variable $global:getNinjaAccessToken
        }

        ## Unknown api endpoint
        elseif ($errorResponseFromNinja.errorMessage -eq "HTTP 404 Not Found") {
          logger("Ninja does not recognize the api endpoint: $apiEndpoint (404 not found)")
          return $null # no need to retry if its an unknown endpoint
        }
      }
      
      ## Response from end point provided no error information/provided odd response.
      else {
        $response = $null
        logException -Message "Unknown error occured while invoking api $apiEndpoint" -ExceptionObj $exceptionObj
      }
    }

    $retries--
  }
  
  # No response
  if ($null -eq $response) {
    logger("Unable to get a response from the api")
  }

  return $response
}

## Function::matchNmapScanMacsToNinjaMacs - Match nmap scanned devices with managed Ninja devices using mac address
function matchNmapScanMacsToNinjaMacs {
  param(
    $nmapScanResults
    ,$ninjaDeviceList
  )

  $result = [pscustomobject]@{
    knownDevices = @()
    unknownDevices = @()
  }

  ## Loop through nmap scan nodes
  logger("Looking for device matches between nmap scan and ninja devices...")
  foreach ($node in $nmapScanResults) {
    # Find a ninja device that has the same mac address as the current nmap node
    $found = $ninjaDeviceList | Where-Object -property macaddresses -like $node.mac

    $device = [pscustomobject]@{
      nmap_hostname = $node.hostname
      nmap_ipv4 = $node.ipv4
      nmap_mac = $node.mac

      ninja_system_name = $found.systemName
      ninja_dns_name = $found.dnsName
      ninja_ip_addresses = $found.ipAddresses
      ninja_mac_addresses = $found.macaddresses
      ninja_public_ip = $found.publicIp
      ninja_approval_status = $found.approvalStatus
    }

    # Found a known device
    if ($null -ne $found) {
      $result.knownDevices += $device
    }

    # Found an unkown device
    else {
      $result.unknownDevices += $device
    }
  }

  logger("Found $($result.knownDevices.count) known devices")
  logger("Found $($result.unknownDevices.count) unknown devices")

  return $result
}


####################################
## Begin Application
####################################
Write-Host('--------------------------------------------------------------------------
Network Overseer v1.0 - Evan Greene
--------------------------------------------------------------------------')

### Ensure basic requirements met
### Ensure basic requirements met
checkForRequirements

## Perform nmap scan to get ips and mac addresses
$nmapScanResults = nmapPingScan -target $nmapTarget -pathToXmlResults "$logPath\scanresult.xml"

## Pull data from Ninja
$devices = getNinjaDevices

# Find unknown and known devices
$overseerMap = matchNmapScanMacsToNinjaMacs -nmapScanResults $nmapScanResults -ninjaDeviceList $devices

# Device info stored in $overseerMap
#$overseerMap.knownDevices
#$overseerMap.knownDevices
