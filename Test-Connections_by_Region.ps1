$deploymentIDs = Get-PWCMDBfromCSV | where datacenter -like '*UK SOuth*' | select deploymentID, datacenter -Unique
$ErrorActionPreference = 'SilentlyContinue'

foreach ($deploymentID in $deploymentIDs) {
    $servers = Get-ServersInMasDeployment -DeploymentId $deploymentID.DeploymentID
    foreach ($server in $servers) {
        $connection = Test-Connection $server -Count 1
        if (!$connection) {
            $server
            Write-Error -Message "Server $server not responding"

            $output = [ordered]@{
                Server = $server
            }
        
        $badserver = New-Object PSOBject -Property $output
        $badserver | Export-Csv -Path c:\temp\UK_South_Outage.csv -NoTypeInformation -Append

        }
    }
}


$deploymentIDs = Get-PWCMDBfromCSV | where datacenter -like '*UK SOuth*' | select sqlservername, sqlservermirror, datacenter -Unique
$ErrorActionPreference = 'SilentlyContinue'

foreach ($deploymentID in $deploymentIDs) {
    
    $connection = Test-Connection $deploymentID.sqlservername -Count 1
    if (!$connection) {
        Write-Error -Message "Server $server not responding"
        $deploymentID.sqlservername
        $output = [ordered]@{
            Server = $deploymentID.sqlservername
        }
        
        $badserver = New-Object PSOBject -Property $output
        $badserver | Export-Csv -Path c:\temp\UK_South_Outage_SQL.csv -NoTypeInformation -Append
    }

    $connection = Test-Connection $deploymentID.sqlservermirror -Count 1
    if (!$connection) {
        Write-Error -Message "Server $server not responding"
        $deploymentID.sqlservermirror
        $output = [ordered]@{
        Server = $deploymentID.sqlservermirror
        }
        
        $badserver = New-Object PSOBject -Property $output
        $badserver | Export-Csv -Path c:\temp\UK_South_Outage_SQL.csv -NoTypeInformation -Append
    }
}
    
