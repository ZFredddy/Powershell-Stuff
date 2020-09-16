function save-encryptedpassword
{
<#
.Synopsis
   Encrypt password and save to file
.DESCRIPTION
   Encrypt password using Windows login dialog and encrypt to file in documents folder
#>
    $username = $env:USERNAME.ToLower()
    $domain = $env:USERDNSDOMAIN.ToLower()
    $SecurePassword = Read-Host -Prompt "Enter password for $username@$domain" -AsSecureString
    $path = [Environment]::GetFolderPath('Personal')
    $outpath = "$path\encrypted_password1.txt"
    $SecurePassword | ConvertFrom-SecureString | Set-Content "$outpath"
    write-host "Password saved to $outpath"
}

function Save-CredentialObjectToFile {
    [CmdletBinding()]
    Param (
        [string]$SaveCredentialFilename = 'encrypted_credentials1.txt'
    )

    BEGIN {
        $Path = [Environment]::GetFolderPath('Personal')
        $Username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $CredPath = "$path\$SaveCredentialFilename"
    }

    PROCESS {
        $Credential = Get-Credential -Message "Please enter credentials to be used for remote server access" -UserName $Username
        $Credential | Export-CliXml $CredPath
        Write-Output $Credential
    }
}

function Get-CredentialObjectFromFile {
    [CmdletBinding()]
    Param (
        [string]$SaveCredentialFilename = 'encrypted_credentials1.txt'
    )

    BEGIN {
        $Path = [Environment]::GetFolderPath('Personal')
        $CredPath = "$path\$SaveCredentialFilename"
    }

    PROCESS {
        if (!(Test-Path -Path $CredPath)) {
            Write-Warning "Credential file does not exist, enter credentials to continue"
            $Credential = Save-CredentialObjectToFile
            Write-Output $Credential
        }
        else {
            $Credential = Import-CliXml $CredPath
            Write-Output $Credential
        }
    }

    END {}
}

function Get-PWODBCDsn {
    [CmdletBinding()]
    Param 
        (
        [string]$deploymentID,
        [switch]$IncludeOFDatabases,
        [ValidateSet("app","idx","ics","adm","imb","all")]
        [string]$ServerType
        )

    $cred = Get-CredentialObjectFromFile

    if ($ServerType -eq 'All') {
        $servers = Get-ServersInMasDeployment -DeploymentId $deploymentID* -ServerNameType DNSHostName
    }
    else {
        $servers = Get-ServersInMasDeployment -DeploymentId $deploymentID*$ServerType* -ServerNameType DNSHostName
    }

    $OdbcDsn = @() # = [collections.arraylist]::New()
    foreach ($appserver in $servers)
    {
        Write-verbose "Getting ODBC data from $appserver"
        $Odbcs = Invoke-Command -ComputerName $appserver -credential $cred -ScriptBlock `
        {
            if ($using:IncludeOFDatabases) {
                Get-OdbcDsn -Platform '64-bit' | where name -like *pw*-db*
            }
            else {
                Get-OdbcDsn -Platform '64-bit' | where name -like *pw-db*
            }
        } 

        foreach ($odbc in $odbcs) {
            $object = [ordered]@{
                AppServer = $appserver
                Database = $ODBC.Attribute["Database"]
                Server = $ODBC.Attribute["Server"]
                FailOverPartner = $ODBC.Attribute["Failover_Partner"]
            }
            $ODBCDsn += New-Object PSOBject -Property $object
            #$ODBCDsn.add({New-Object PSOBject -Property $object})
        }
    }
    $OdbcDsn
}

function Update-PWOdbcDsn
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$DeploymentID,
        [Parameter(Mandatory=$true)]
        [String]$SqlAlias,
        [Parameter(Mandatory=$true)]
        [String]$SqlMirrorAlias,
        [Switch]$IncludeOFDatabases,
        [ValidateSet("app","idx","ics","adm","imb")]
        [string]$ServerType
    )

    $cred = Get-CredentialObjectFromFile
    $servers = Get-ServersInMasDeployment -DeploymentId $DeploymentID*$ServerType* -ServerNameType DNSHostName
    $OdbcDsn = @()

    foreach ($appserver in $servers)
    {
        Write-verbose "Getting ODBC in $appserver"
        $OdbcDsn16 = Invoke-Command -ComputerName $appserver -credential $cred -ScriptBlock `
        {
            if ($using:IncludeOFDatabases) {
                $ODBCDSNs = Get-OdbcDsn -Platform '64-bit' | where name -like *-pw*-db*
            }
            else {
                $ODBCDSNs = Get-OdbcDsn -Platform '64-bit' | where name -like *-pw-db*
            }

            foreach ($odbc in $ODBCDSNs)
            {
                $ODBC |  Set-OdbcDsn -SetPropertyValue "Server=$using:SqlAlias"
                $ODBC |  Set-OdbcDsn -SetPropertyValue "Failover_Partner=$using:SqlMirrorAlias"
            }

            if ($using:IncludeOFDatabases) {
                Get-OdbcDsn -Platform '64-bit' | where name -like *-pw*db*
            }
            else {
                Get-OdbcDsn -Platform '64-bit' | where name -like *-pw-db*
            }
        } 

        foreach ($odbc in $OdbcDsn16) {
            $object = [ordered]@{
                AppServer = $appserver
                Database = $ODBC.Attribute["Database"]
                Server = $ODBC.Attribute["Server"]
                FailOverPartner = $ODBC.Attribute["Failover_Partner"]
            }
            $ODBCDsn += New-Object PSOBject -Property $object
        }
    }
    $OdbcDsn
}

function Get-PWDatacenter {
    $status = ('Delivery', 'With Prof Svcs', 'Migrating Data', 'User Testing')
    #$datacenters = Get-PWCMDBfromCSV | where {($_.projectstatus -in $status) -and ($_.datacenter -ne "")} | select datacenter -Unique
    $datacenters = Import-Csv \\bentleyhosting.com\shares\mas\Misc\PWMAS_Reporting\datacenters_and_timezones.csv
    $datacenters
}

function Save-PWEncryptedKey
{
<#
.Synopsis
   Encrypt key for decrypting PW Admin passwords and save to file
.DESCRIPTION
   Encrypt password key using PWPS_DAB function
#>
    if (-not(Get-Module -name PWPS_DAB)) {Import-Module -name pwps_dab}
    $path = [Environment]::GetFolderPath('Personal')
    $outpath = "$path\encrypted_key.txt"
    Save-SecureStringToEncryptedFile -Prompt "Enter key from Password Manager" -FileName $outpath
}

function New-PWBentleyUser
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$EmailAddress,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Windows", "Federated")]
        [String] $AccountType,
        [switch]$Admin = $false
    )

    $TextInfo = (Get-Culture).TextInfo
    $UserName = $EmailAddress.Split("@")[0]
    $UserName = $TextInfo.ToTitleCase($UserName)

    $Description = $EmailAddress.Split("@")[0] -replace ("[.]"," ")
    $Description = $TextInfo.ToTitleCase($Description)

    $EmailAddress = $EmailAddress.ToLower()
    $EmailAddress

    if ($AccountType -eq "Windows")
    {
        $user = New-PWUser -WindowsDomainUser -UserName $UserName -SecProvider "BENTLEY" -Description $Description -Identity $EmailAddress -Email $EmailAddress
    }
    if ($AccountType -eq "Federated")
    {
        $user = New-PWUser -FederatedIdentityUser -UserName $UserName -Description $Description -Identity $EmailAddress -Email $EmailAddress
    }
    if ($Admin)
    {
        Add-PWGroupMember -GroupID 1 -UserName $user.username
    }
}

function Connect-PWdatasource {
<#
.Synopsis
   Login to datasource
.DESCRIPTION
   Login to datasource using admin credentials after prompting for datasource name
.EXAMPLE
	connect-pwdatasource -datasource abc-us-pw
#>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$datasource
    )

    BEGIN {
        $CredsPath = '\\bentleyhosting.com\shares\MAS\Misc\PowerShell_Scripts\DatasourceSetup'
        $DecryptedCreds = $CredsPath + '\datasources and creds.csv'
        $EncryptedCreds = $CredsPath + '\datasources and creds encrypted.csv'
        $KeyFile = 'encrypted_key.txt'
        $KeyPath = [Environment]::GetFolderPath('Personal')
        $KeyFullFile= $KeyPath + '\' + $KeyFile
        $VerbosePreference = 'SilentlyContinue'

        $ErrorActionPreference= 'silentlycontinue'
        if (Get-PWCurrentDatasource) {Close-PWConnection > $null}
        #$ErrorActionPreference= 'Continue'

        #Check for existence of keyfile
        If (Test-Path $KeyFullFile) {
            $Key = (Get-ClearTextFromEncryptedFile $KeyFullFile)
        }
        Else {
            Write-error "MaS Keyfile $KeyFullFile not found"
            exit
        }
    }
    PROCESS {
        $ds = import-csv $EncryptedCreds | Where-Object datasource -eq $datasource -ErrorAction Stop -ErrorVariable DatasourceError
        if ($ds) {
            if (-not(Get-Module -Name PWPS)) {
                Import-Module -Name "C:\Program Files (x86)\Bentley\ProjectWise\bin\PowerShell\pwps\PWPS.dll"
            }

            $pwps = Get-Module | Where-Object name -eq 'PWPS'

            $CurrentDataSource = ($ds.fqdn + ':' + $ds.datasource)
            $DecryptedPassword = Decrypt-String -Encrypted $ds.pwadminpass -Passphrase $key | ConvertTo-SecureString -AsPlainText -Force
            New-PWLogin -DatasourceName $CurrentDataSource -UserName $ds.pwadmin -Password $DecryptedPassword -DoNotCreateWorkingDirectory -ErrorVariable ConnectError

            if ($ConnectError) {
                Write-Warning 'Bad username or password in credentials file'
            }
        }
        else {
            Write-Error "Datasource $datasource not found or invalid name"
            $a = $False
        }
        return $a
    }
    END {
    }
}

function Search-PWDatasource
{
    <#
.Synopsis
   Retrieve list of datasources
.DESCRIPTION
   Retrieve list of datasources from credentials file
.EXAMPLE
	search-pwdatasource -datasource abc*
.EXAMPLE
    search-pwdatasource -datasource *neu*
.EXAMPLE
    search-pwdatasource -datasource *-pw

#>

    [CmdletBinding()]
    Param(
        [string]$datasource = "*"
    )

    $DataSourceFile = '\\bentleyhosting.com\shares\MAS\Misc\PowerShell_Scripts\DatasourceSetup\datasources and creds encrypted.csv'
    $DataSources = import-csv $DataSourceFile

    $d = $datasources | Where-Object datasource -like $datasource | Select-Object fqdn, datasource
    return $d
}

function get-pwCMDB
{
<#
.Synopsis
   Retrieve list of datasources from CMDB
.DESCRIPTION
   Retrieve list of datasources from CMDB SharePoint list
.EXAMPLE
	get-pwCMDB
#>

    [CmdletBinding()]
    Param(
        [string]$DataSource = "*",
        [string]$AccountName = "*",
        [string]$FQDN = "*"
    )

    Add-Type -Path "c:\Program Files\Common Files\microsoft shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.Client.dll" 
    Add-Type -Path "c:\Program Files\Common Files\microsoft shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.Client.Runtime.dll"

    $path = [Environment]::GetFolderPath('Personal')

    if (-not(Get-Module -Name SPOMod)) 
    {
        import-module "\\bentleyhosting.com\shares\MAS\Misc\PowerShell_Scripts\Modules\SPOMod\SPOMod.psm1"
    }

    #set-location "c:\scripts"
    #VARS
    #$username = ([adsi]"LDAP://$(whoami /fqdn)").mail
    $domainname = $env:USERNAME.ToLower()
    $domain = $env:USERDNSDOMAIN.ToLower()
    $username = $domainname + "@" + $domain
    $url = 'https://bentley.sharepoint.com/sites/PWCloudServices'
    $password = convertto-securestring (get-content "$path\encrypted_password1.txt") #-key (1..16)
    #END VARS

    #---------------------------------------
    #START Get list of datasources from CMDB
    #---------------------------------------

    Write-Verbose "Connecting to $url"
 
    $ctx = New-Object Microsoft.SharePoint.Client.ClientContext($Url)
    $ctx.Credentials = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($Username, $password)
    $ctx.ExecuteQuery()  
    $global:ctx = $ctx

    Write-Verbose "Retrieving datasources from SharePoint"

    $cmdb = Get-SPOListItems -ListTitle CMDB -IncludeAllProperties $true -Recursive | Sort-Object title, Datasource_x0020_Name_x0028_s_x0

    Write-Verbose "Retrieved $($CMDB.Count) datasources"

    #$cmdb = $cmdb | Where-Object {($_.title -like $account) -and ($_.Datasource_x0020_Name_x0028_s_x0 -like $datasource) -and ($_.fqdn -like $fqdn)}
    return $cmdb
}

function Get-PWCMDBfromCSV
{
    [CmdletBinding()]
    Param(
        [string]$DataSource,
        [string]$AccountName,
        [string]$FQDN
    )

    $OutPath = "\\bentleyhosting.com\shares\MAS\Misc\PWMAS_Reporting"
    $cmdb = Import-Csv "$OutPath\cmdb.csv" | Where-Object {($_.FQDN -NE '') -OR ($_.'Datasource Name' -NE '')} 
    $cmdb = $cmdb | Where-Object {($_.'datasource name' -like "*$DataSource*")}
    $cmdb = $cmdb | Where-Object {($_.accountname -like "*$AccountName*")}
    $cmdb = $cmdb | Where-Object {($_.fqdn -like "*$FQDN*")}

    $cmdb = $cmdb | Sort-Object AccountName, FQDN, "Datasource Name"
    return $cmdb
}

function connect-pwCMDB
{
    Add-Type -Path "c:\Program Files\Common Files\microsoft shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.Client.dll" 
    Add-Type -Path "c:\Program Files\Common Files\microsoft shared\Web Server Extensions\16\ISAPI\Microsoft.SharePoint.Client.Runtime.dll"

    $path = [Environment]::GetFolderPath('Personal')

    if (-not(Get-Module -Name SPOMod)) 
    {
        import-module "\\bentleyhosting.com\shares\MAS\Misc\PowerShell_Scripts\Modules\SPOMod\SPOMod.psm1"
    }

    #set-location "c:\scripts"
    #VARS
    #$username = ([adsi]"LDAP://$(whoami /fqdn)").mail
    $domainname = $env:USERNAME.ToLower()
    $domain = $env:USERDNSDOMAIN.ToLower()
    $username = $domainname + "@" + $domain
    $url = 'https://bentley.sharepoint.com/sites/PWCloudServices'
    $password = convertto-securestring (get-content "$path\encrypted_password1.txt") #-key (1..16)
    #END VARS

    #---------------------------------------
    #START Get list of datasources from CMDB
    #---------------------------------------

    Write-Verbose "Connecting to $url"
 
    $ctx = New-Object Microsoft.SharePoint.Client.ClientContext($Url)
    $ctx.Credentials = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($Username, $password)
    $ctx.ExecuteQuery()  
    $global:ctx = $ctx
}

function Get-PWDataSourceFromList
{
    [CmdletBinding()]
    param(  
        [Parameter(
            Position = 0, 
            Mandatory = $true, 
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)
        ]
        [String]$filter
    ) 

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $datasource = Import-Csv -Path '\\bentleyhosting.com\shares\MAS\Misc\PowerShell_Scripts\DatasourceSetup\datasources and creds encrypted.csv'
    $datasource = $datasource | where-object {$_.datasource -like "$filter"} | Select-Object datasource | Sort-Object datasource

    $form = New-Object System.Windows.Forms.Form 
    $form.Text = "Select a Datasource"
    $form.Size = New-Object System.Drawing.Size(300, 600) 
    $form.StartPosition = "CenterScreen"

    #OK Button
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Point(75, 520)
    $OKButton.Size = New-Object System.Drawing.Size(75, 23)
    $OKButton.Text = "OK"
    $OKButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.AcceptButton = $OKButton
    $form.Controls.Add($OKButton)

    #Cancel Button
    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Point(150, 520)
    $CancelButton.Size = New-Object System.Drawing.Size(75, 23)
    $CancelButton.Text = "Cancel"
    $CancelButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
    $form.CancelButton = $CancelButton
    $form.Controls.Add($CancelButton)

    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(10, 20) 
    $label.Size = New-Object System.Drawing.Size(280, 20) 
    $label.Text = "Please select a computer:"
    $form.Controls.Add($label) 

    $listBox = New-Object System.Windows.Forms.ListBox 
    $listBox.Location = New-Object System.Drawing.Point(10, 40) 
    $listBox.Size = New-Object System.Drawing.Size(260, 20) 
    $listBox.Height = 480
#    $listBox.SelectedItems = 

    foreach ($ds in $datasource)
    {
        [void] $ListBox.Items.Add($ds.datasource.ToLower())
    }
    $form.Controls.Add($listBox) 
    $form.Topmost = $True
    $result = $form.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK)
    {
        $x = $listBox.SelectedItem
        $x
    }
}

function Connect-PWDataSourceFromList
{
    [CmdletBinding()]
    Param(
        [string]$filter
    )
    
    $datasource = get-pwdatasourcefromlist -filter $filter
    
    if ($datasource)
    {
        Write-Verbose "Connecting to $datasource"
        Connect-PWdatasource -datasource $datasource
    }
}

Function Get-PWUserWithDuplicateEmail
{
<#
.Synopsis
   Retrieve list of accounts with duplicate emails. 
.DESCRIPTION
   Retrieve list of accounts with duplicate emails. Bentley accounts and accounts with no email addresses are ingored.
   All accounts are written to https://bentley.sharepoint.com/sites/PWCloudServices/Shared%20Documents/Forms/AllItems.aspx in the form of DatasourceName_users.csv
   Duplicate accounts are written to https://bentley.sharepoint.com/sites/PWCloudServices/Shared%20Documents/Forms/AllItems.aspx in the form of DatasourceName_DuplicateEmails.csv
.EXAMPLE
	Get-PWUserWithDuplicateEmail -datasource DatasourceName
#>
    [CmdletBinding()]
    param(  
        [Parameter(
            Position = 0, 
            Mandatory = $true, 
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)
        ]
        [String]$datasource
    ) 

    BEGIN
    {
        $outfile = "D:\SharePoint\ProjectWise Cloud Services - Docume\IMS Federation\" + $datasource + "_Users.csv"
        $outfiledups = "D:\SharePoint\ProjectWise Cloud Services - Docume\IMS Federation\" + $datasource + "_DuplicateEmails.csv"
    }

    PROCESS
    {
        Write-Verbose "Connecting to $datasource"
        Connect-PWdatasource $datasource
        Write-Verbose "Retrieving users"
        $users = Get-PWUserByLastLogin

        Write-Verbose "Retrieved $($users.count) users"
        Write-Verbose "Removing *bentley.com from all users"
        $users2 = $users | Where-Object {$_.email -notLike "*bentley.com"}
        Write-Verbose "$($users.count - $users2.count) bentley.com accounts removed"
        Write-Verbose "Removing users without email addresses"
        $users3 = $users2 | Where-Object {$_.email -ne ""} | Sort-Object email
        Write-Verbose "$($users2.count - $users3.count) empty email address accounts removed"
        $users4 = $users3 | Select-Object -Property @{Name="email"; Expression = {$_.email.tolower()}} -Unique
    
        $dups = @()
        foreach ($u in $users4)
        {
            $check = $users3 | Where-Object {$_.email -eq $u.email}
            if ($check.count -gt 1)
            {
                Write-Verbose "Found $($u.email) as a duplicate"
                foreach ($c in $check)
                {
                    $dups += $c
                }
            }
        }
        Write-Verbose "Found $($dups.count) accounts with duplicate email addresses"
    
        $dups | Select-Object CreationDate, LastLogin, Description, Disabled, Email, UserID, Name, SecProvider, Type | Export-Csv -Path $outfiledups -NoTypeInformation
        $users | Select-Object CreationDate, LastLogin, Description, Disabled, Email, UserID, Name, SecProvider, Type | Export-Csv -Path $outfile -NoTypeInformation
        write-verbose "============================================================"
        Close-PWConnection
    }

    END
    {

    }
}

Function Test-PWDataSourceInCMDB
{
<#
.Synopsis
   Test datasource from PWIS is in CMDB. 
.DESCRIPTION
   Dmskrnl.cfg is read and compared to the CMDB testing all datasources exist.
.EXAMPLE
	Test-PWDataSourceInCMDB -servername ServerName
.Example
    Test-PWDataSourceInCMDB -servername ServerName -RefreshCMDB
    This will re-read the CMDB SharePoint site and rewrite the $CMDB variable
#>
    [CmdletBinding()]
    param(  
        [Parameter(
            Position = 0, 
            Mandatory = $true, 
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)
        ]
        [String]$ServerName,
        [Switch]$RefreshCMDB
    )

    BEGIN
    {     
        if ($RefreshCMDB)
        {    
            $global:cmdb = Get-pwCMDB
        }

        $missing = @()
        $output = @()
    }

    PROCESS
    {
        Write-Verbose "Testing $servername"
        $DSConfig = Get-PWDSConfigEntry -Server $ServerName
        #$dsconfig
        $cmdb1 = $cmdb | Where-Object fqdn -eq $ServerName | Select-Object fqdn, title, Datasource_x0020_Name_x0028_s_x0 
        foreach ($ds in $dsconfig)
        {
            if ($ds.InternalName -notin $cmdb1.Datasource_x0020_Name_x0028_s_x0)
            {
                $output = [ordered]@{
                    HostName = $ds.hostname
                    Name = $ds.name
                    Datasource = $ds.internalname
                }
                $missing += New-Object PSOBject -Property $output
                Write-Error "$($ds.InternalName) Not Found"
            }
        }
    }

    END
    {

        $body = ""
        $to = "Bryan Sapen <bryan.sapen@bentley.com>"
        $from = "Bryan Sapen <bryan.sapen@bentley.com>"
        $smtpServer = "smtp.bentley.com"
        $subject = "Missing Datasources in CMDB"

        $body = "<HTML><HEAD><META http-equiv=""Content-Type"" content=""text/html; charset=utf-8"" /><TITLE></TITLE></HEAD>"
        $body += "<BODY bgcolor=""#FFFFFF"" style=""font-size: Small; font-family: TAHOMA; color: #000000""><P>"


        $body += "As of "
        $body += get-date
        $body += ", the following datasources are not listed in the CMDB."
        $body += "<br><br>"

        foreach ($d in $missing)
        {
            $name = $d.name -replace "\\p{Pd}", "-"
            $line = $d.hostname + " | " + $d.datasource + " | " + $name + "<br>"
            $body += $line
        }
        $body += "<br><br>"
        $body += "Regards,<br>"
        $body += "Bryan Sapen<br>"
        $body += "Cloud Consultant<br>"
        $body += "Bentley Systems, Inc.<br>"

        $body
        send-mailmessage -to $to -from $from -subject $subject -bodyashtml $body -smtpServer $smtpServer -Verbose

        $missing  
    }
}

Function Test-PWDataSourceInCredsFile
{
<#
.Synopsis
   Test that datasource from PWIS is in CMDB. 
.DESCRIPTION
   Dmskrnl.cfg is read and compared to the CMDB testing all datasources exist.
.EXAMPLE
	Test-PWDataSourceInCMDB -servername ServerName
.Example
    Verify-PWDataSourceInCMDB -servername ServerName -RefreshCMDB
    This will re-read the CMDB SharePoint site and rewrite the $CMDB variable
#>
    [CmdletBinding()]
    param(  
        [Parameter(
            Position = 0, 
            Mandatory = $true, 
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true)
        ]
        [String]$datasource,
        [Switch]$RefreshCMDB
    ) 

    BEGIN
    {
        $EncryptedFile = '\\bentleyhosting.com\shares\MAS\Misc\PowerShell_Scripts\DatasourceSetup\datasources and creds encrypted.csv'
        $Creds = import-csv $EncryptedFile | Sort-Object title, fqdn, Datasource
        $status = ('Delivery', 'With Prof Svcs', 'Migrating Data', 'Pre-Release (IT Complete)', 'User Testing')

        if ($RefreshCMDB)
        {    
            $global:cmdb = Get-pwCMDB
        }
    }

    PROCESS
    {
        Write-Verbose "Retrieving datasource $($datasource) from CMDB"
        $cmdb1 = $cmdb | Where-Object Datasource_x0020_Name_x0028_s_x0 -eq $datasource
        if (![string]::IsNullOrEmpty($cmdb1.Datasource_x0020_Name_x0028_s_x0) -and $cmdb1.Project_x0020_Status -in $status)
        {
            Write-verbose "Checking credentials for $($cmdb1.Datasource_x0020_Name_x0028_s_x0)"
            $c = $creds | Where-Object datasource -eq $cmdb1.Datasource_x0020_Name_x0028_s_x0
            if ($c)
            {
                Write-Verbose "Datasource $datasource found in credentials file"
                $connected = Connect-PWdatasource -datasource $cmdb1.Datasource_x0020_Name_x0028_s_x0
                write-verbose $connected -Verbose
                if ($connected -eq 'true')
                {
                    write-verbose "Closing connection to $($cmdb1.Datasource_x0020_Name_x0028_s_x0)" -Verbose
                    close-pwconnection
                }
                else
                {
                    Write-Error "Datasource $($cmdb1.Datasource_x0020_Name_x0028_s_x0) bad credentials in credentials file"
                }
            }
            else
            {
                Write-Error "Datasource $($cmdb1.Datasource_x0020_Name_x0028_s_x0) missing credentials in credentials file"
            }
        }
    }

    END
    {
    }
}

function Get-PWServerFarmBySQLServerName
{
    [CmdletBinding()]
    Param(
        [string]$sqlserver,
        [Switch]$RefreshCMDB,
        [Switch]$Datasources
    )
    $global:allservers = @()

    if ($RefreshCMDB -or !$CMDB)
    {    
        $global:cmdb = Get-pwCMDB
    }

    if (!$Datasources)
    {
        $output = $cmdb | Where-Object {($_.SQLServers -like "*$sqlserver*") -and ($_.ServerFarmStatus -eq "Delivery")} | Select-Object title, fqdn, datacenter -Unique
        foreach($o in $output)
        {
            $output3 = [ordered]@{
            AccountName = $o.title
            FQDN = $o.fqdn
            Datacenter = $o.datacenter
            Database = $sqlserver
            }
        $global:allservers += New-Object PSOBject -Property $output3
        }
        $allservers
    }

    if ($Datasources)
    {
        $output = $cmdb | Where-Object {($_.SQLServers -like "*$sqlserver*") -and ($_.ServerFarmStatus -eq "Delivery")} | Select-Object title, fqdn, datacenter, Datasource_x0020_Name_x0028_s_x0 -Unique
        foreach($o in $output)
        {
            $output3 = [ordered]@{
            AccountName = $o.title
            FQDN = $o.fqdn
            Datacenter = $o.datacenter
            Database = $sqlserver
            Datasource = $o.Datasource_x0020_Name_x0028_s_x0
            }
        $global:allservers += New-Object PSOBject -Property $output3
        }
        $allservers
    }
}

function Verify-PWCredentials
{

<#
.Synopsis
   Test Credentials. 
.DESCRIPTION
   Get credentials and verify against datasource
.EXAMPLE
	Verify-PWCredentials -servername ServerName
    ServerName is required. If not included, all servers will be verified
.Example
    Verify-PWCredentials -datasource DatasourceName
.EXAMPLE
    Verify-PWCredentials -RefreshCMDB
    This parameter will refresh the $CMDB variable
.EXAMPLE
    Verify-PWCredentials -TestLogin
    This will check for credentials in the creds file and will also attempt a login to each datasource
#>
    [CmdletBinding()]
    param(  
        [Parameter(Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [String]$ServerName = "*",
        [String]$Datasource,
        [Switch]$RefreshCMDB,
        [Switch]$TestLogin
    )

    BEGIN
    {
        if ($RefreshCMDB -or !$CMDB)
        {    
            $global:cmdb = Get-pwCMDB | Sort-Object title, fqdn, Datasource_x0020_Name_x0028_s_x0
        }

        $global:BadCreds = @()
        $Status = ('Delivery','Pre-Release (IT complete)','With Prof Svcs', 'User Testing')
        $cmdb2 = $cmdb | Where-Object {($_.fqdn -like "*$servername*" ) -and ($_.Datasource_x0020_Name_x0028_s_x0 -like "*$datasource*") -and ($_.Project_x0020_Status -in $status)}
        $cmdb2 = $cmdb2 | Sort-Object fqdn, Datasource_x0020_Name_x0028_s_x0
        $CredsFile = '\\bentleyhosting.com\shares\MAS\Misc\PowerShell_Scripts\DatasourceSetup\datasources and creds encrypted.csv'
        $creds = import-csv $CredsFile | Sort-Object title, fqdn, Datasource
    }

    PROCESS
    {
        foreach($item in $cmdb2)
        {
            write-verbose "Checking $($item.fqdn):$($item.Datasource_x0020_Name_x0028_s_x0)"
            $c = $creds | Where-Object datasource -eq $item.Datasource_x0020_Name_x0028_s_x0
            if (!$c)
            {
                $output = [ordered]@{
                FQDN = $item.FQDN
                Datasource = $item.Datasource_x0020_Name_x0028_s_x0
                Message = "Missing record in credentials file"
                }
                $global:badcreds += New-Object PSOBject -Property $output
            }
            else
            {
                if ($TestLogin)
                {
                    Write-Verbose "Connecting to $($item.fqdn):$($item.Datasource_x0020_Name_x0028_s_x0)"
                    $connected = Connect-PWdatasource -datasource $item.Datasource_x0020_Name_x0028_s_x0
                    if ($connected -eq 'true')
                    {
                        Write-Verbose "Connected"
                        write-verbose "Closing connection to $($item.fqdn):$($item.Datasource_x0020_Name_x0028_s_x0)"
                        Close-PWConnection
                    }
                    else
                    {
                        $output = [ordered]@{
                        FQDN = $item.FQDN
                        Datasource = $item.Datasource_x0020_Name_x0028_s_x0
                        Message = "Invalid record in credentials file"
                        }
                        $global:badcreds += New-Object PSOBject -Property $output
                    }
                }
            }
        }
    }

    END
    {
        $global:badcreds
    }
}

function Get-PWUsersForDecommissioning
{

<#
.Synopsis
   Return recent users. 
.DESCRIPTION
   Returns a list of recent users in all datasources of a FQDN. 60 days is the default
.EXAMPLE
	Get-PWUsersForDecommissining -FQDN ServerName
    FQDN is required.
.Example
    Get-PWUsersForDecommissining -FQDN ServerName -DaysAgo 30
    Get list of users that have logged in during the last 30 days
.EXAMPLE
    Get-PWUsersForDecommissining -FQDN ServerName -Unique
    Get a unique list of users that have logged in during the last 60 days. 
    Unique list does not include datasource or lastlogin
#>

    [CmdletBinding()]
    param(  
        [String]$FQDN,
        [INT]$DaysAgo = 60,
        [Switch]$Unique
    )

    BEGIN
    {
        $CredsFile = "\\bentleyhosting.com\shares\MAS\Misc\PowerShell_Scripts\DatasourceSetup\datasources and creds encrypted.csv"
        $creds = import-csv $CredsFile | Where-Object fqdn -eq $fqdn | Sort-Object fqdn, Datasource
        $users = @()
    }

    PROCESS
    {
        foreach($c in $creds)
        {
            Write-Verbose "Connecting to $($c.fqdn):$($c.Datasource)"
            $connected = Connect-PWdatasource -datasource $c.datasource
            if ($connected -eq 'true')
            { 
                write-verbose "Retrieving users from the last $($daysago) days"
                $recentusers = Get-PWUserByLastLogin -DaysAgo $daysago -Since | 
                    Where-Object {($_.email -notlike "*@bentley.com") -and ($_.username -notlike "_*")} | 
                    Select-Object username, description, email, lastlogin
                Close-PWConnection
                foreach ($u in $recentusers)
                {
                    $output = [ordered]@{
                        FQDN = $c.fqdn
                        Datasource = $c.Datasource
                        Username = $u.username
                        Description = $u.description
                        Email = $u.email
                        LastLogin = $u.lastlogin
                        }
                        $users += New-Object PSOBject -Property $output
                }
            }
        }
    }

    END
    {
        if ($unique)
        {
            $users | Select-Object -Property fqdn, username, description, email -Unique
        }
        else
        {
            $users
        }
    }
}

function Encrypt-String($String, $Passphrase, $salt="DaveSaltCrypto", $init="IV_Password", [switch]$arrayOutput) 
{ 
    # Create a COM Object for RijndaelManaged Cryptography 
    $r = new-Object System.Security.Cryptography.RijndaelManaged 
    # Convert the Passphrase to UTF8 Bytes 
    $pass = [Text.Encoding]::UTF8.GetBytes($Passphrase) 
    # Convert the Salt to UTF Bytes 
    $salt = [Text.Encoding]::UTF8.GetBytes($salt) 
 
    # Create the Encryption Key using the passphrase, salt and SHA1 algorithm at 256 bits 
    $r.Key = (new-Object Security.Cryptography.PasswordDeriveBytes $pass, $salt, "SHA1", 5).GetBytes(32) #256/8 
    # Create the Intersecting Vector Cryptology Hash with the init 
    $r.IV = (new-Object Security.Cryptography.SHA1Managed).ComputeHash( [Text.Encoding]::UTF8.GetBytes($init) )[0..15] 
     
    # Starts the New Encryption using the Key and IV    
    $c = $r.CreateEncryptor() 
    # Creates a MemoryStream to do the encryption in 
    $ms = new-Object IO.MemoryStream 
    # Creates the new Cryptology Stream --> Outputs to $MS or Memory Stream 
    $cs = new-Object Security.Cryptography.CryptoStream $ms,$c,"Write" 
    # Starts the new Cryptology Stream 
    $sw = new-Object IO.StreamWriter $cs 
    # Writes the string in the Cryptology Stream 
    $sw.Write($String) 
    # Stops the stream writer 
    $sw.Close() 
    # Stops the Cryptology Stream 
    $cs.Close() 
    # Stops writing to Memory 
    $ms.Close() 
    # Clears the IV and HASH from memory to prevent memory read attacks 
    $r.Clear() 
    # Takes the MemoryStream and puts it to an array 
    [byte[]]$result = $ms.ToArray() 
    # Converts the array from Base 64 to a string and returns 
    return [Convert]::ToBase64String($result) 
} 
 
function Decrypt-String($Encrypted, $Passphrase, $salt="DaveSaltCrypto", $init="IV_Password") 
{ 
    # If the value in the Encrypted is a string, convert it to Base64 
    if($Encrypted -is [string]){ 
        $Encrypted = [Convert]::FromBase64String($Encrypted) 
       } 
 
    # Create a COM Object for RijndaelManaged Cryptography 
    $r = new-Object System.Security.Cryptography.RijndaelManaged 
    # Convert the Passphrase to UTF8 Bytes 
    $pass = [Text.Encoding]::UTF8.GetBytes($Passphrase) 
    # Convert the Salt to UTF Bytes 
    $salt = [Text.Encoding]::UTF8.GetBytes($salt) 
 
    # Create the Encryption Key using the passphrase, salt and SHA1 algorithm at 256 bits 
    $r.Key = (new-Object Security.Cryptography.PasswordDeriveBytes $pass, $salt, "SHA1", 5).GetBytes(32) #256/8 
    # Create the Intersecting Vector Cryptology Hash with the init 
    $r.IV = (new-Object Security.Cryptography.SHA1Managed).ComputeHash( [Text.Encoding]::UTF8.GetBytes($init) )[0..15] 
 
    # Create a new Decryptor 
    $d = $r.CreateDecryptor() 
    # Create a New memory stream with the encrypted value. 
    $ms = new-Object IO.MemoryStream @(,$Encrypted) 
    # Read the new memory stream and read it in the cryptology stream 
    $cs = new-Object Security.Cryptography.CryptoStream $ms,$d,"Read" 
    # Read the new decrypted stream 
    $sr = new-Object IO.StreamReader $cs 
    # Return from the function the stream 
    Write-Output $sr.ReadToEnd() 
    # Stops the stream     
    $sr.Close() 
    # Stops the crypology stream 
    $cs.Close() 
    # Stops the memory stream 
    $ms.Close() 
    # Clears the RijndaelManaged Cryptology IV and Key 
    $r.Clear() 
} 

function Get-ServersInMasDeployment {
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [String] $DeploymentId,
        [ValidateSet("Name", "DNSHostName")]
        [String] $ServerNameType
    )

    $ErrorActionPreference = 'Continue'
    if (!$ServerNameType){$ServerNameType = "Name"}

    $ActiveDirectoryModule = Get-Module ActiveDirectory
    if (!$ActiveDirectoryModule) {
        Write-Verbose 'Importing ActiveDirectory Module'
        Import-Module ActiveDirectory
    }

    Write-Verbose ('Getting Servers in DeploymentId {0}' -f $DeploymentId)
   # try {
        $ServerList = Get-ADComputer -Filter ('Name -like "{0}"' -f "$DeploymentId*") -ErrorAction Stop
        if ($ServerList) {
            if ($ServerNameType -eq "Name") {$ServerList.Name.tolower()}
            if ($ServerNameType -EQ "DNSHostName") {$ServerList.DNSHostName.ToLower()}
        }
   # }
   # catch {
   #     throw $PSItem
   # }
}

function Get-IpLocation 
{
<#
.SYNOPSIS
    Retrieves Geo IP location data
.DESCRIPTION
    This command retrieves the Geo IP Location data for one or more IP addresses
.PARAMETER IPAddress <String[]>
    Specifies one or more IP Addresses for which you want to retrieve data for.
.EXAMPLE
    Get-MvaIpLocation -ipaddress '124.26.123.240','123.25.96.8'
.EXAMPLE
    '124.26.123.240','123.25.96.8' | Get-MvaIpLocation
.LINK
    https://get-note.net/2019/01/18/use-powershell-to-find-ip-geolocation
.INPUTS
    System.String
.OUTPUTS
    System.Management.Automation.PSCustomObject
.NOTES
    Author: Mario van Antwerpen
    Website: https://get-note.net
#>
    [cmdletbinding()]
    [OutputType([System.Management.Automation.PSCustomObject])]
    Param (
        [Parameter(ValueFromPipeline, Mandatory, Position = 0, HelpMessage = "Enter an IP Address")]
        [ValidateScript({
            if ($_ -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
                $true
            } else {
                Throw "$_ is not a valid IPv4 Address!"
            }
        })]
        [string[]]$ipaddress
    )

    begin {
        Write-Verbose -message "Starting $($MyInvocation.Mycommand)"
    }

    process {
        foreach ($entry in $ipaddress) {
            $restUrl = "http://ip-api.com/json/$entry"

            try {
                Write-Verbose -Message "Connecting to rest endpoint"
                $result = Invoke-RestMethod -Method get -Uri $restUrl
                Write-output $result
            }
            catch {
                Write-Verbose -Message "Catched and error"
                $PSCmdlet.ThrowTerminatingError($PSitem)
            }
        }
    }

    end {
        Write-Verbose -message "Ending $($MyInvocation.Mycommand)"
    }
}

#=========================================================

function Get-PWStorageForMoveToAzureFiles {

<#
.Synopsis
   Returns a report of all storage areas in a deployment 
.DESCRIPTION
   Returns a report of all storage areas in a deployment
   along with a running total showing suggested Azure Files volume
   Running total will be less than 3TB
.EXAMPLE
	Get-StorageForMoveToAzureFiles -FQDN ServerName
    FQDN is required.
.Example
    Get-StorageForMoveToAzureFiles -FQDN ServerName -OutFilePath "D:\some path\some childpath"
    Use quotes around path with spaces 
#>

    [CmdletBinding()]
        param(  
            [String]$FQDN,
            [String]$OutFilePath = "c:\temp"
        )

    New-Item -ItemType Directory -Force $OutFilePath | Out-Null
    $AllStorageReport = @()

    $filename = $fqdn -replace "\*", ""
    
    $today = get-date -Format "yyyyMMdd"
    $OutFile = "PWStorageReportForAzureFiles_" + $filename + "_" + $today + ".csv"
    $FQDNS = Search-PWDatasource | Where-Object fqdn -like $fqdn | select fqdn -Unique

    foreach ($F in $FQDNS)
    {
        $StorageSum = 0
        $FQDNStorageReport = @()
        $datasources = Search-PWDatasource | where fqdn -eq $F.fqdn | Sort-Object datasource

        foreach ($d in $datasources)
        {
            Connect-PWdatasource $d.datasource
            Get-PWCurrentDatasource
            $AllStorage = Get-PWStorageDiskUsage
            foreach ($Storage in $AllStorage) {

                $StorageSum = $StorageSum + $Storage.TotalStorageAreaFileSize

                $WindowsStoragePath = $Storage.path -replace "/fs\d/","/"
                #Write-Output $WindowsStoragePath
                $WindowsStorageRootPathItems = $storage.path -split "/"
                $WindowsStorageRootPath = "//" + $WindowsStorageRootPathItems[2] + "/" + $WindowsStorageRootPathItems[3]
                #write-output $WindowsStorageRootPath

                $output = [ordered]@{
                    FQDN = $f.fqdn
                    Datasource = $d.datasource
                    TotalDiskGB = [math]::round($storage.TotalStorageAreaFileSize / 1gb, 3)
                    StorageID = $Storage.StorageID
                    StorageName = $Storage.StorageName
                    WindowsPath = $Storage.Path
                }
                $FQDNStorageReport += New-Object PSOBject -Property $output
            }
        }

        $output = [ordered]@{
            FQDN = ""
            Datasource = ""
            TotalDiskGB = [math]::round($StorageSum / 1gb, 1)
            StorageID = ""
            StorageName = ""
            WindowsPath = ""
            AzurePath = ""
        }
        $FQDNStorageReport += New-Object PSOBject -Property $output

        $FQDNStorageReport | Export-Csv -Path $OutFilePath\$OutFile -NoTypeInformation -Force
        $AllStorageReport += $FQDNStorageReport
    }

    $AllStorageReport | Out-GridView
    Close-PWConnection

    if ($GenerateRobocopyScript) {
        Generate-PWStorageToAzureFilesScript
    }

    if ($GeneratePWStorageUpdateScript) {
        Generate-PWStorageUpdateScript
    }
}

function Generate-PWStorageToAzureFilesScript {

    $PSOutFile = "Copy-PWStorageToAzureFiles_" + $filename + ".ps1"

    '$StartTime = $(get-date)' | Out-File -FilePath $OutFilePath\$PSOutFile 
    '$VerbosePreference = "Continue"' | Out-File -FilePath $OutFilePath\$PSOutFile -Append
     '' | Out-File -FilePath $OutFilePath\$PSOutFile -Append
    
    foreach ($StorageArea in $AllStorageReport) {
        $outstring = '$source = "' + ("$($StorageArea.WindowsPath)" -replace "/","\") + '"'
        $outstring | Out-File -FilePath $OutFilePath\$PSOutFile -Append
        $outstring = '$target = "' + ("$($storageArea.AzurePath)" -replace "/","\") + '"'
        $outstring | Out-File -FilePath $OutFilePath\$PSOutFile -Append
        if ($AzureStorageRootPath) {
            'robocopy $source $target /mir /r:0 /w:0 /np /ndl /mt:4' | Out-File -FilePath $OutFilePath\$PSOutFile -Append
            '' | Out-File -FilePath $OutFilePath\$PSOutFile -Append
        }
    }

    '$EndTime = $(get-date)' | Out-File -FilePath $OutFilePath\$PSOutFile -Append
    '$ElapsedTime = $EndTime - $StartTime' | Out-File -FilePath $OutFilePath\$PSOutFile -Append 
    '$TotalTime = "{0:HH:mm:ss}" -f ([datetime]$elapsedTime.Ticks)' | Out-File -FilePath $OutFilePath\$PSOutFile -Append
    'Write-Verbose "Total time = $TotalTime"' | Out-File -FilePath $OutFilePath\$PSOutFile  -Append
}

function Generate-PWStorageUpdateScript {

    $PSOutFile = "Update-PWStorageForAzureFiles_" + $filename + ".ps1"

    '$VerbosePreference = "Continue"' | Out-File -FilePath $OutFilePath\$PSOutFile
    '' | Out-File -FilePath $OutFilePath\$PSOutFile -Append

    $datasources = $AllStorageReport | select datasource -Unique

    foreach ($datasource in $datasources) {
        'Write-Output "Logging into datasource ' + $($datasource.datasource) +'"' | Out-File -FilePath $OutFilePath\$PSOutFile -Append
        'Connect-PWdatasource ' + $($datasource.datasource) | Out-File -FilePath $OutFilePath\$PSOutFile -Append
        '' |  Out-File -FilePath $OutFilePath\$PSOutFile -Append

        'if (Get-PWCurrentDatasource) {' | Out-File -FilePath $OutFilePath\$PSOutFile -Append
            $StorageAreas = $AllStorageReport | where datasource -eq $datasource.datasource
    
            foreach ($StorageArea in $StorageAreas) {
                $NewPath = $StorageArea.AzurePath -replace "/","\"
                '     Update-PWStorageAreaProperties -Name ' + $($StorageArea.StorageName) + ' -Path ' + $NewPath | Out-File -FilePath $OutFilePath\$PSOutFile -Append
            }
        '}' | Out-File -FilePath $OutFilePath\$PSOutFile -Append
        'else {Write-warning "Unable to log into datasource ' + $($datasource.datasource) + '"}"' | Out-File -FilePath $OutFilePath\$PSOutFile -Append
        '' |  Out-File -FilePath $OutFilePath\$PSOutFile -Append
    }
}

#=========================================================

function Get-PWOnlineCount {

<#
.Synopsis
    Returns a count of PWONLINE users in all datasources
#>

    [CmdletBinding()]
        param(  
            [String]$FQDN
        )

    $FQDNS = Search-PWDatasource | Where-Object fqdn -like $fqdn | select fqdn -Unique
    $PWOnlineUsers = @()

    foreach ($F in $FQDNS)
    {
        $datasources = Search-PWDatasource | where fqdn -eq $F.fqdn | Sort-Object datasource
        foreach ($d in $datasources)
        {
            Connect-PWdatasource $d.datasource
            Get-PWCurrentDatasource
            $PWOnlineUsers += Get-PWUsersByMatch -SecProvider PWONLINE -Enabled
        }
    }

    $UniquePWOnlineUsers = $PWOnlineUsers | select username, description, email, type, secprovider -Unique

    Write-Verbose "Number of users $($UniquePWOnlineUsers.count)"
    $UniquePWOnlineUsers | Out-GridView

    return $UniquePWOnlineUsers

    Write-Verbose "Number of users $($UniquePWOnlineUsers.count)"
}

#=========================================================

Function Install-PWPS_DABToRemoteServer
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$Server,
        [Parameter(Mandatory=$true)] 
        [System.Management.Automation.CredentialAttribute()] 
        $Credential
    )

    Invoke-Command -ComputerName $server -credential $cred -ScriptBlock `
    {

        $PwPsDabModuleName = 'pwps_dab'
        $onlineModule = Find-Module -Name $PwPsDabModuleName -Repository PSGallery
        $localModule = Get-Module -ListAvailable -Name $PwPsDabModuleName
        if ($localModule.Version -lt $onlineModule.Version) {
            foreach ($module in $localModule) {
                Write-Verbose "Uninstalling any old versions of $PwPsDabModuleName modules"
                Uninstall-Module -Name $PwPsDabModuleName -Force
            }
            Write-Verbose "$PwPsDabModuleName Module does not exist, installing..."
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
            Install-Module -Name $PwPsDabModuleName -Force
        }
        else {
            Write-Verbose "$PwPsDabModuleName Module is Up to Date"
        }

        #Import-Module -Name pwps_dab
    }
}
#=========================================================

########################################################################################################################
function Invoke-SqlCommand() {
    [cmdletbinding(DefaultParameterSetName="integrated")]Param (
        [Parameter(Mandatory=$true)][Alias("Serverinstance")][string]$Server,
        [Parameter(Mandatory=$true)][string]$Database,
        [Parameter(Mandatory=$true, ParameterSetName="not_integrated")][string]$Username,
        [Parameter(Mandatory=$true, ParameterSetName="not_integrated")][string]$Password,
        [Parameter(Mandatory=$false, ParameterSetName="integrated")][switch]$UseWindowsAuthentication = $true,
        [Parameter(Mandatory=$true)][string]$Query,
        [Parameter(Mandatory=$false)][int]$CommandTimeout=0
    )
    
    #build connection string
    $connstring = "Server=$Server; Database=$Database; "
    If ($PSCmdlet.ParameterSetName -eq "not_integrated") { $connstring += "User ID=$username; Password=$password;" }
    ElseIf ($PSCmdlet.ParameterSetName -eq "integrated") { $connstring += "Trusted_Connection=Yes; Integrated Security=SSPI;" }
    
    #connect to database
    $connection = New-Object System.Data.SqlClient.SqlConnection($connstring)
    $connection.Open()
    
    #build query object
    $command = $connection.CreateCommand()
    $command.CommandText = $Query
    $command.CommandTimeout = $CommandTimeout
    
    #run query
    $adapter = New-Object System.Data.SqlClient.SqlDataAdapter $command
    $dataset = New-Object System.Data.DataSet
    $adapter.Fill($dataset) | out-null
    
    #return the first collection of results or an empty array
    If ($dataset.Tables[0] -ne $null) {$table = $dataset.Tables[0]}
    ElseIf ($table.Rows.Count -eq 0) { $table = New-Object System.Collections.ArrayList }
    
    $connection.Close()
    return $table
}
########################################################################################################################


function Move-PWAuditTrailRecordByUser {

<#
.Synopsis

    Archive audit trail records by username
    [_]accounts and [*]accounts are done automatically
.DESCRIPTION

    Script archives to a secondary table in the same database all
    audit trail records by username. This process is done in blocks of 10,000.
    It uses Begin and commit transactions and rollbacks 
.EXAMPLE
	Move-PWAuditTrailRecordByUser -pwDBservername mydeployment-pw-db.bentleyhosting.com -DatabaseName *pw-db* -PWUserFilter pw*,*of* -AuditTrailRecordsToRemain 42000
    Leave out the -PWDBServername to use the current server, -DatabaseName is required
#>

    [CmdletBinding()]
        param(  
            [String]$pwDBservername = $env:computername,
            [boolean]$backup_dms_audt = $false,
            [Parameter(Mandatory=$true)][string]$DatabaseName = $(throw "-DatabaseName is required."),
            [string[]]$PWUserFilter,
            [int]$AuditTrailRecordsToRemain = 50000
        )

    $ErrorActionPreference = 'Continue'
    $DebugPreference = 'Continue'
    $VerbosePreference = 'Continue'
    $MasArchiveTable = 'dms_audt_MAS_archive'
    [int]$BlockSize = 10000
    [int]$BlocksToRemain = $AuditTrailRecordsToRemain/$BlockSize

    if ($DatabaseName) {$DatabaseName = $DatabaseName.Replace("*","%")}
    if ($PWUserFilter) {$PWUserFilter = $PWUserFilter.Replace("*","%")}

    #all databases
    $query = "SELECT name FROM master.sys.databases WHERE name like '$DatabaseName'"
    $query
    $databases = Invoke-SqlCommand -Server $pwDBservername -Database master -Query $query 
    Write-Verbose "Returned $($databases.count) PW Databases"

    $i=0
    $topusers = @()

    foreach ($db in $databases) {
        $i+=1
        Write-Verbose "Getting top users from database $($db.name) [$i of $($databases.count)]"
        $query = "SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = N'dms_audt'"
        $exists = Invoke-SqlCommand -Server $pwDBservername -Database $($db.name) -Query $query 
        if ($exists) {
            $query = "SELECT '$($db.name)', o_userno, o_username, count(o_username) as counter "
            $query += "FROM [$($db.name)].dbo.dms_audt "
            $query += "WHERE o_username like '[_]%' OR o_username like '[*]%' "

            foreach ($PWUser in $PWUserFilter) {
                $query += "OR o_username like '$PWUser' "
            }

            $query += "GROUP BY o_username, o_userno "
            $query += "ORDER BY count(*) DESC;"
            #$query
            $topusers += Invoke-SqlCommand -Server $pwDBservername -Database $($db.name) -Query $query 
        }
        else {
            Write-Warning "$($db.name) is not a PW Datasource"
        }
    }

    $largeusers = $topusers | where counter -gt $AuditTrailRecordsToRemain
    $databases = $largeusers | select @{Label="Name";Expression={($_.column1)}} -Unique | Sort-Object Name
    $largeusers

    $i=0
    foreach ($db in $databases) {
        #================================================
        # Create dms_audt_MAS_archive if does not exist
        #================================================
        $i+=1
        Write-Verbose "Processing database $($db.name) [$i of $($databases.count)]"
        $query = "SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = N'$MasArchiveTable'"
        $exists = Invoke-SqlCommand -Server $pwDBservername -Database $($db.name) -Query $query    
        if (!$exists) {
            Write-Verbose "Creating table [$($db.name)]"
            $query = "Select Top 0 * into $MasArchiveTable from dms_audt"
            $exists = Invoke-SqlCommand -Server $pwDBservername -Database $($db.name) -Query $query 
        }
    
        #================================================
        # Backup dms_audt if required
        #================================================

        if ($backup_dms_audt) {
            Write-Verbose "Creating backup of dms_audt table"
            $query = "SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = N'$MasArchiveTable'"
            $exists = Invoke-SqlCommand -Server $pwDBservername -Database $($db.name) -Query $query 
            if (!$exists) {
                $query = "Select * into $MasArchiveTable from dms_audt"
                $exists = Invoke-SqlCommand -Server $pwDBservername -Database $($db.name) -Query $query 
            }
        }

        #================================================
        #Create index on dms_audt table
        #================================================

        Write-Verbose "Checking for i_$MasArchiveTable index to create"
        $query = "SELECT * FROM sys.indexes WHERE name='i_$MasArchiveTable' AND object_id = OBJECT_ID('dbo.dms_audt')"
        $exists = Invoke-SqlCommand -Server $pwDBservername -Database $($db.name) -Query $query
        if (!$exists) {
            Write-Verbose "Creating i_dms_audt_MAS_archive index"
            $query = "CREATE NONCLUSTERED INDEX [i_$MasArchiveTable] ON [dbo].[dms_audt] "
            $query += "([o_username], [o_acttime]) "
            $query += "INCLUDE ([o_audtno],[o_objtype],[o_objguid],[o_objno],[o_action],[o_userno],[o_comments],[o_numparam1],[o_numparam2],[o_textparam],[o_guidparam],[o_userdesc],[o_itemname],[o_itemdesc],[o_parentguid])"
            $exists = Invoke-SqlCommand -Server $pwDBservername -Database $($db.name) -Query $query 
        }

        #================================================
        # Get list of users in each DB being processed
        #================================================

        $users = $largeusers | where {$_.column1 -eq $db.name}
        foreach ($user in $users) {
            Write-Verbose "Creating records in $MasArchiveTable in $($db.name)"
            #Count total records for username
            Write-Verbose "Counting records for [$($user.o_username)] in $($db.name)"
            $query = "SELECT COUNT(*) FROM dms_audt WHERE o_username = '$($user.o_username)'"
            $count = Invoke-SqlCommand -Server $pwDBservername -Database $($db.name) -Query $query
            $count = $count | Select-Object -ExpandProperty Column1
            Write-Verbose "Found $count audit trail records for [$($user.o_username)] in $($db.name)"
            $loops = [int]($count / $BlockSize) - $BlocksToRemain

            while ($loops -gt 0) {
                # Creating records in dms_audt_mas_archive table
                # Deleting records in dms_audt table
                Write-Verbose "----------------------------------------------------"
                Write-Verbose "$loops loops to go"
                Write-Verbose "Moving dms_audt records for [$($user.o_username)] in $($db.name)"
                $query = "SELECT TOP $BlockSize o_username, o_acttime FROM dms_audt WHERE o_username = '$($user.o_username)' ORDER BY o_acttime ASC"
                Write-Verbose $query
                $records = Invoke-SqlCommand -Server $pwDBservername -Database $($db.name) -Query $query
                $record = $records | Select-Object -Last 1
                Write-Verbose "Maximum date $($record.o_acttime.ToString("MM/dd/yyyy HH:mm:ss.fff")) for [$($user.o_username)]"

                    $procedure =  "BEGIN TRY`n"
                    $procedure += "`tBEGIN TRAN;`n"
                    $query =  "`t`tINSERT INTO $MasArchiveTable SELECT TOP $BlockSize * FROM dms_audt "
                    $query += "WHERE o_username = '$($user.o_username)' "
                    $query += "AND o_acttime <= '$($record.o_acttime.ToString("MM/dd/yyyy HH:mm:ss.fff"))' ORDER BY o_acttime ASC"
                    Write-Verbose $query
                    $procedure += "$query;`n"
                    $query = "`t`tDELETE TOP ($BlockSize) FROM dms_audt "
                    $query += "WHERE o_username = '$($user.o_username)' "
                    $query += "AND o_acttime <= '$($record.o_acttime.ToString("MM/dd/yyyy HH:mm:ss.fff"))'"
                    Write-Verbose $query
                    $procedure += "$query`n" 
                    $procedure += "`tCOMMIT TRAN;`n"
                    $procedure += "END TRY`n"
                    $procedure += "BEGIN CATCH`n"
                    $procedure += "`tIF(@@TRANCOUNT > 0)`n"
                    $procedure += "`tROLLBACK TRAN;`n"
                    $procedure += "`tPRINT 'Transaction rolled back'`n"
                    $procedure += "END CATCH"

                $output = Invoke-SqlCommand -Server $pwDBservername -Database $($db.name) -Query $procedure
                $loops -= 1

                Write-Verbose "----------------------------------------------------"
            }
        }

        #Remove index from dms_audt table
        Write-Verbose "Checking for i_$MasArchiveTable index to drop"
        $query = "SELECT * FROM sys.indexes WHERE name='i_$MasArchiveTable' AND object_id = OBJECT_ID('dbo.dms_audt')"
        $exists = Invoke-SqlCommand -Server $pwDBservername -Database $($db.name) -Query $query
        if ($exists) {
            Write-Verbose "Droping i_$MasArchiveTable index in $($db.name)"
            $query = "DROP INDEX [i_$MasArchiveTable] ON [dbo].[dms_audt]"
            $dropindex = Invoke-SqlCommand -Server $pwDBservername -Database $($db.name) -Query $query 
        }
    }
}



Function Get-PwActivationKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String] $ComputerName
    )

    $key = 'SOFTWARE\Wow6432Node\Bentley\Licensing\1.1'
    $valueName = 'Activation'

    try {
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', "$ComputerName")
        $regkey = $reg.opensubkey($key)
        $regkey.getvalue($valueName)
    } 
    catch [System.Security.SecurityException] {
        "Registry - access denied $($key)"
    } 
    catch {
        $_.Exception.Message
    }
}

function Html-ToText {
 param([System.String] $html)

 # remove line breaks, replace with spaces
 $html = $html -replace "(`r|`n|`t)", " "
 # write-verbose "removed line breaks: `n`n$html`n"

 # remove invisible content
 @('head', 'style', 'script', 'object', 'embed', 'applet', 'noframes', 'noscript', 'noembed') | % {
  $html = $html -replace "<$_[^>]*?>.*?</$_>", ""
 }
 # write-verbose "removed invisible blocks: `n`n$html`n"

 # Condense extra whitespace
 $html = $html -replace "( )+", " "
 # write-verbose "condensed whitespace: `n`n$html`n"

 # Add line breaks
 @('div','p','blockquote','h[1-9]') | % { $html = $html -replace "</?$_[^>]*?>.*?</$_>", ("`n" + '$0' )} 
 # Add line breaks for self-closing tags
 @('div','p','blockquote','h[1-9]','br') | % { $html = $html -replace "<$_[^>]*?/>", ('$0' + "`n")} 
 # write-verbose "added line breaks: `n`n$html`n"

 #strip tags 
 $html = $html -replace "<[^>]*?>", ""

 $html = $html -replace "\?",""
 # write-verbose "removed tags: `n`n$html`n"
  
 # replace common entities
 @( 
  @("&amp;bull;", " * "),
  @("&amp;lsaquo;", "<"),
  @("&amp;rsaquo;", ">"),
  @("&amp;(rsquo|lsquo);", "'"),
  @("&amp;(quot|ldquo|rdquo);", '"'),
  @("&amp;trade;", "(tm)"),
  @("&amp;frasl;", "/"),
  @("&amp;(quot|#34|#034|#x22);", '"'),
  @('&amp;(amp|#38|#038|#x26);', "&amp;"),
  @("&amp;(lt|#60|#060|#x3c);", "<"),
  @("&amp;(gt|#62|#062|#x3e);", ">"),
  @('&amp;(copy|#169);', "(c)"),
  @("&amp;(reg|#174);", "(r)"),
  @("&amp;nbsp;", " "),
  @("&amp;(.{2,6});", "")
 ) | % { $html = $html -replace $_[0], $_[1] }
 # write-verbose "replaced entities: `n`n$html`n"

 return $html
}


function New-PWRandomPassword {
    <#
      .Synopsis
       Generates one or more complex passwords designed to fulfill the requirements for Active Directory
      .DESCRIPTION
       Generates one or more complex passwords designed to fulfill the requirements for Active Directory
      .EXAMPLE
       New-SWRandomPassword
       C&3SX6Kn

       Will generate one password with a length between 8  and 12 chars.
      .EXAMPLE
       New-SWRandomPassword -MinPasswordLength 8 -MaxPasswordLength 12 -Count 4
       7d&5cnaB
       !Bh776T"Fw
       9"C"RxKcY
       %mtM7#9LQ9h

       Generates a password with a length of 4 containing atleast one char from each InputString that will start with a letter from 
       the string specified with the parameter FirstChar
      .OUTPUTS
       [String]
      .NOTES
       Written by Simon Wåhlin, blog.simonw.se
       I take no responsibility for any issues caused by this script.
      .FUNCTIONALITY
       Generates random passwords
      .LINK
       http://blog.simonw.se/powershell-generating-random-password-for-active-directory/
   
    #>
    [CmdletBinding(DefaultParameterSetName='FixedLength',ConfirmImpact='None')]
    [OutputType([String])]
    Param
    (
        # Specifies minimum password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='RandomLength')]
        [ValidateScript({$_ -gt 0})]
        [Alias('Min')] 
        [int]$MinPasswordLength = 19,
        
        # Specifies maximum password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='RandomLength')]
        [ValidateScript({
                if($_ -ge $MinPasswordLength){$true}
                else{Throw 'Max value cannot be lesser than min value.'}})]
        [Alias('Max')]
        [int]$MaxPasswordLength = 20,

        # Specifies a fixed password length
        [Parameter(Mandatory=$false,
                   ParameterSetName='FixedLength')]
        [ValidateRange(1,2147483647)]
        [int]$PasswordLength = 20,
        
        # Specifies an array of strings containing charactergroups from which the password will be generated.
        # At least one char from each group (string) will be used.
        [String[]]$InputStrings = @('abcdefghijkmnpqrstuvwxyz', 'ABCEFGHJKLMNPQRSTUVWXYZ', '23456789', '!^#%@$'),

        # Specifies a string containing a character group from which the first character in the password will be generated.
        # Useful for systems which requires first char in password to be alphabetic.
        [String] $FirstChar,
        
        # Specifies number of passwords to generate.
        [ValidateRange(1,2147483647)]
        [int]$Count = 1

    )
    Begin {
        Function Get-Seed{
            # Generate a seed for randomization
            $RandomBytes = New-Object -TypeName 'System.Byte[]' 4
            $Random = New-Object -TypeName 'System.Security.Cryptography.RNGCryptoServiceProvider'
            $Random.GetBytes($RandomBytes)
            [BitConverter]::ToUInt32($RandomBytes, 0)
        }
    }
    Process {
        For($iteration = 1;$iteration -le $Count; $iteration++){
            $Password = @{}
            # Create char arrays containing groups of possible chars
            [char[][]]$CharGroups = $InputStrings

            # Create char array containing all chars
            $AllChars = $CharGroups | ForEach-Object {[Char[]]$_}

            # Set password length
            if($PSCmdlet.ParameterSetName -eq 'RandomLength')
            {
                if($MinPasswordLength -eq $MaxPasswordLength) {
                    # If password length is set, use set length
                    $PasswordLength = $MinPasswordLength
                }
                else {
                    # Otherwise randomize password length
                    $PasswordLength = ((Get-Seed) % ($MaxPasswordLength + 1 - $MinPasswordLength)) + $MinPasswordLength
                }
            }

            # If FirstChar is defined, randomize first char in password from that string.
            if($PSBoundParameters.ContainsKey('FirstChar')){
                $Password.Add(0,$FirstChar[((Get-Seed) % $FirstChar.Length)])
            }
            # Randomize one char from each group
            Foreach($Group in $CharGroups) {
                if($Password.Count -lt $PasswordLength) {
                    $Index = Get-Seed
                    While ($Password.ContainsKey($Index)){
                        $Index = Get-Seed                        
                    }
                    $Password.Add($Index,$Group[((Get-Seed) % $Group.Count)])
                }
            }

            # Fill out with chars from $AllChars
            for($i=$Password.Count;$i -lt $PasswordLength;$i++) {
                $Index = Get-Seed
                While ($Password.ContainsKey($Index)){
                    $Index = Get-Seed                        
                }
                $Password.Add($Index,$AllChars[((Get-Seed) % $AllChars.Count)])
            }
            Write-Output -InputObject $(-join ($Password.GetEnumerator() | Sort-Object -Property Name | Select-Object -ExpandProperty Value))
        }
    }
}


function Sync-PWConfigFile {

    #*---------------------------------------------------------------------------------------------------------------------------------------------------**#
    ## <author>Juan.Riat</author>
    ## 
    ## Script to be used for Syncing ProjectWise dmskrnl.cfg and DmsAfpEngineConf.xml in ProjectWise 3.2+ 
    ##
    ## Example
    <#
    powershell.exe -ExecutionPolicy Bypass \\bentleyhosting.com\shares\MAS\Scripts\ProjectWise\Sync-ProjectWise-Config-File.ps1 -DeploymentId 'juanpw83' `
                    -SourceComputerName 'juanpw83app01.bentleyhosting.com' -DestinationComputerName 'juanpw83app02.bentleyhosting.com' -Type 'dmskrnl'

    powershell.exe -ExecutionPolicy Bypass \\bentleyhosting.com\shares\MAS\Scripts\ProjectWise\Sync-ProjectWise-Config-File.ps1 -DeploymentId 'juanpw83' `
                    -SourceComputerName 'juanpw83app01.bentleyhosting.com' -DestinationComputerName 'juanpw83app02.bentleyhosting.com' -Type 'dmsafp'

    powershell.exe -ExecutionPolicy Bypass \\bentleyhosting.com\shares\MAS\Scripts\ProjectWise\Sync-ProjectWise-Config-File.ps1 -DeploymentId 'juanpw83' `
                    -SourceComputerName 'juanpw83app01.bentleyhosting.com' -DestinationComputerName 'juanpw83app02.bentleyhosting.com' -Type 'all'
    #>                           
    #*---------------------------------------------------------------------------------------------------------------------------------------------------**#

    param (
        [Parameter(Mandatory=$true)]
        [String] $DeploymentId,
        
        [Parameter(Mandatory=$true)]
        [String] $SourceComputerName,

        [Parameter(Mandatory=$true)]
        [String[]] $DestinationComputerName,
        
        [Parameter(Mandatory=$true)]
        [ValidateSet("dmskrnl","dmsafp","all")]
        [String] $Type  
    )

    $Credential = Get-Credential -Message 'Credentials' -UserName ('bentleyhosting\{0}-pw-svc' -f $deploymentId)

    # Functions
    function createFileVersion {
        param (
            [Parameter(Mandatory=$true)]
            [ValidateScript({Test-Path -Path $PSItem})]
            [String] $Path    
        )
        $file = Get-Item -Path $Path
        $fileName = $file.Name
        $pathParentFolder = $file.Directory.FullName
        $archivedFiles = (Get-ChildItem $pathParentFolder | Where-Object { $_ -match "$($fileName).\d"} | Sort-Object {($_.Name -replace "[^\d]","") -as [int]})
        if ($null -ne $archivedFiles) {
            $currentArchivedFileName = ($archivedFiles[-1]).Name
        }
        
        if ($null -eq $currentArchivedFileName) {
            $nextArchiveNumber = '1'
        }
        else {
            $nextArchiveNumber = [Int](($currentArchivedFileName -split '\.')[-1])+1
        }
        $destinationPath = "{0}\$($fileName).{1}" -f $pathParentFolder,$nextArchiveNumber
        
        try {
            Copy-Item -Path $Path -Destination $destinationPath -ErrorAction Stop
        }
        catch {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }

    function Protect-BcoPwConfigFile {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true)]
            [ValidateScript({Test-Path -Path $PSItem -PathType 'Leaf'})]
            [String] $Path,

            [Parameter(Mandatory=$true)]
            [String] $PwInstallPath,

            [Parameter(Mandatory=$true)]
            [ValidateSet("dmskrnl","dmsafp")]
            [String] $Type,

            [Parameter(Mandatory=$false)]
            [PSCredential]
            $Credential,

            [Parameter(Mandatory=$true)]
            [String] $Destination,

            [Parameter(Mandatory=$false)]
            [Switch] $Force,

            [Parameter(Mandatory=$false)]
            [Switch] $PassThru,

            [Parameter(Mandatory=$false)]
            [Switch] $Backup
        )

        $dmscfgcopyFilePath = '{0}\bin\dmscfgcopy.exe' -f $PwInstallPath
        $inputFile = Get-Item -Path $Path -ErrorAction 'Stop'
        $outputFile = $null
    
        if (Test-Path -Path $Destination -PathType 'Leaf') {
            $outputFile = $Destination
        }
        elseif (Test-Path -Path $Destination -PathType 'Container') {
            $outputFile = '{0}\{1}' -f $Destination.TrimEnd('\'),$inputFile.Name
        }
        else {
            if ((Test-Path -Path (Split-Path -Path $Destination -Parent) -PathType 'Container') -and 
                ($Destination -notmatch '\\$')) {
            
                    $outputFile = $Destination
            }
            else {
                throw ('Could not find a part of the path {0}.' -f $Destination)
            }   
        }

        if (Test-Path -Path $outputFile -PathType 'Leaf') {
            if ($PSBoundParameters['Force'] -ne $true) {
                throw ('The destination {0} already exist. Provide -Force to overwrite it.' -f $outputFile)
            }

            if ($Type -eq 'dmskrnl') {
                if ($null -eq (Get-Content -Path $outputFile | Where-Object {$_ -match '^\s*\[.*\]\s*$'})) {
                    throw ('dmscfgcopy requires {0} to be in a valid dmskrnl format.' -f $outputFile)
                }
            }
            elseif ($Type -eq 'dmsafp') {
                if ($null -eq [xml](Get-Content -Path $outputFile -ErrorAction SilentlyContinue)) {
                    throw ('dmscfgcopy requires {0} to be in a valid xml format.' -f $outputFile)
                }
            }

            if ($Backup.IsPresent -eq $true) {
                createFileVersion -Path $outputFile
            }
        }

        do {
            $tempOutputPath = '{0}\{1}' -f $env:TEMP,(Get-Random)
        } while (Test-Path -Path $tempOutputPath)
        New-Item -Path $tempOutputPath -ItemType 'Directory' -Force | Out-Null

        $stdOutPath = ('{0}\StdOut.log' -f $tempOutputPath)
    
        if ($Type -eq 'dmskrnl') {
            $encProcessArguments = "-type $Type",'-enc','-pre',"`"$Path`"","`"$outputFile`""
        }
        elseif ($Type -eq 'dmsafp') {
            $encProcessArguments = "-type $Type",'-enc',"`"$Path`"","`"$outputFile`""
        }

        $params = @{
            FilePath = $dmscfgcopyFilePath 
            ArgumentList = $encProcessArguments
            Wait = $True
            NoNewWindow = $True 
            PassThru = $True 
            ErrorAction = 'Stop'
            RedirectStandardOutput = $stdOutPath
        }
    
        if ($null -ne $Credential ) {
            $params.Add("Credential",$Credential)
        }

        try {
            $proc = Start-Process @params
            if ($proc.ExitCode -ne 0) {
                $stdOutError = Get-Content -Path $stdOutPath | Out-String
                throw ("{0} exited with an exit code of {1}. Error: {2}" -f $dmscfgcopyFilePath,$proc.ExitCode,$stdOutError)
            }
        }
        catch {
            throw $PSItem    
        }
        finally {
            Remove-Item -LiteralPath $tempOutputPath -Force -Confirm:$false -Recurse -ErrorAction 'SilentlyContinue'
        }

        if ($PSBoundParameters['PassThru'] -eq $true) {
            return (Get-item -Path $outputFile)
        }
    }

    function Unprotect-BcoPwConfigFile {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true)]
            [ValidateScript({Test-Path -Path $PSItem -PathType 'Leaf'})]
            [String] $Path,

            [Parameter(Mandatory=$true)]
            [String] $PwInstallPath,

            [Parameter(Mandatory=$true)]
            [ValidateSet("dmskrnl","dmsafp")]
            [String] $Type,

            [Parameter(Mandatory=$false)]
            [PSCredential]
            $Credential,

            [Parameter(Mandatory=$true)]
            [String] $Destination,

            [Parameter(Mandatory=$false)]
            [Switch] $Force,

            [Parameter(Mandatory=$false)]
            [Switch] $PassThru
        )

        $dmscfgcopyFilePath = '{0}\bin\dmscfgcopy.exe' -f $PwInstallPath
        $inputFile = Get-Item -Path $Path -ErrorAction 'Stop'
        $outputFile = $null

        if (Test-Path -Path $Destination -PathType 'Leaf') {
            $outputFile = $Destination    
        }
        elseif (Test-Path -Path $Destination -PathType 'Container') {
            $outputFile = '{0}\{1}' -f $Destination.TrimEnd('\'),$inputFile.Name
        }
        else {
            if ((Test-Path -Path (Split-Path -Path $Destination -Parent) -PathType 'Container') -and 
                ($Destination -notmatch '\\$')) {
            
                    $outputFile = $Destination
            }
            else {
                throw ('Could not find a part of the path {0}.' -f $Destination)
            }   
        }

        if ((Test-Path -Path $outputFile -PathType 'Leaf') -and ($PSBoundParameters['Force'] -ne $true)) {
            throw ('The destination {0} already exist. Provide -Force to overwrite it.' -f $Destination)
        }

        do {
            $tempOutputPath = '{0}\{1}' -f $env:TEMP,(Get-Random)
        } while (Test-Path -Path $tempOutputPath)
        New-Item -Path $tempOutputPath -ItemType 'Directory' -Force | Out-Null

        $tempOutputFile = '{0}\{1}' -f $tempOutputPath,$inputFile.Name
        $stdOutPath = ('{0}\StdOut.log' -f $tempOutputPath)
        $decProcessArguments = "-type $Type",'-dec',"`"$Path`"","`"$tempOutputFile`"" 
    
        $params = @{
            FilePath = $dmscfgcopyFilePath 
            ArgumentList = $decProcessArguments
            Wait = $True
            NoNewWindow = $True 
            PassThru = $True 
            ErrorAction = 'Stop'
            RedirectStandardOutput = $stdOutPath
        }
    
        if ($null -ne $Credential ) {
            $params.Add("Credential",$Credential)
        }

        try {
            $proc = Start-Process @params
            if ($proc.ExitCode -ne 0) {
                $stdOutError = Get-Content -Path $stdOutPath | Out-String
                throw ("{0} exited with an exit code of {1}. Error: {2}" -f $dmscfgcopyFilePath,$proc.ExitCode,$stdOutError)
            }
        
            Copy-Item -Path $tempOutputFile -Destination $outputFile -Force -ErrorAction 'Stop'
        }
        catch {
            throw $PSItem    
        }
        finally {
            Remove-Item -LiteralPath $tempOutputPath -Force -Confirm:$false -Recurse -ErrorAction 'SilentlyContinue'
        }

        if ($PSBoundParameters['PassThru'] -eq $true) {
            return (Get-item -Path $outputFile)
        }
    }

    function Sync-BcoPwConfigFile {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true)]
            [String] $ComputerName,

            [Parameter(Mandatory=$true)]
            [String[]] $DestinationComputerName,

            [Parameter(Mandatory=$true)]
            [String] $PwInstallPath,

            [Parameter(Mandatory=$true)]
            [ValidateSet("dmskrnl","dmsafp")]
            [String] $Type,

            [Parameter(Mandatory=$true)]
            [PSCredential]
            $Credential,

            [Parameter(Mandatory=$false)]
            [Switch] $SkipDestinationServiceRestart
        )

        if ($Type -eq 'dmskrnl') {
            $pwCfgPath = '{0}\bin\dmskrnl.cfg' -f $PwInstallPath.TrimEnd('\')
            $tempPwCfgPath = '{0}\bin\dmskrnl_dmscfgcopy.cfg' -f $PwInstallPath.TrimEnd('\')
        }
        elseif ($Type -eq 'dmsafp') {
            $pwCfgPath = '{0}\bin\DmsAfpEngineConf.xml' -f $PwInstallPath.TrimEnd('\')
            $tempPwCfgPath = '{0}\bin\DmsAfpEngineConf_dmscfgcopy.xml' -f $PwInstallPath.TrimEnd('\')
        }

        try { 
            $sourceSession = New-PsSession -ComputerName $ComputerName -Credential $Credential -ErrorAction 'Stop'
    
            $decryptFunction = Get-ChildItem -Path Function: | Where-Object {$_.Name -eq 'Unprotect-BcoPwConfigFile'}

            $decryptedFile = Invoke-Command -Session $sourceSession -ScriptBlock {
                New-Item -Path ('Function:{0}' -f $Using:decryptFunction.Name) -Value $Using:decryptFunction.Definition | Out-Null
                Unprotect-BcoPwConfigFile -Path $Using:pwCfgPath -PwInstallPath $Using:PwInstallPath -Type $Using:Type `
                                            -Destination $Using:tempPwCfgPath -PassThru -Force
            }

            foreach ($server in $DestinationComputerName) {
                try {
                    $copy = Invoke-Command -Session $sourceSession -ErrorAction 'Stop' -ScriptBlock {
                        $decryptedFilePath = $Using:decryptedFile.FullName
                        try {
                            $session = New-PsSession -ComputerName $Using:server -Credential $Using:Credential -ErrorAction 'Stop'

                            Copy-Item -ToSession $session -Path $decryptedFilePath -Destination $decryptedFilePath `
                                        -Force -ErrorAction 'Stop' | Out-Null
                        }
                        catch {
                            throw ('Failed to copy {0}:{1} to {2}:{1}. Error: {3}') -f 
                                    $Using:ComputerName,$decryptedFilePath,$Using:server,$PSItem.Exception
                        }
                        finally {
                            $session | Remove-PSSession -ErrorAction 'SilentlyContinue'
                        }
                    }
                }
                catch {
                    throw $PSItem
                }

                try {
                    $destinationSession = New-PsSession -ComputerName $server -Credential $Credential -ErrorAction 'Stop' 

                    $encryptFunction = Get-ChildItem -Path Function: | Where-Object {$_.Name -eq 'Protect-BcoPwConfigFile'}
                    $createFileVersionFunction = Get-ChildItem -Path Function: | Where-Object {$_.Name -eq 'createFileVersion'}

                    $encryptedFile = Invoke-Command -Session $destinationSession -ErrorAction 'Stop' -ScriptBlock {
                        try {
                            New-Item -Path ('Function:{0}' -f $Using:createFileVersionFunction.Name) -Value $Using:createFileVersionFunction.Definition | Out-Null
                            New-Item -Path ('Function:{0}' -f $Using:encryptFunction.Name) -Value $Using:encryptFunction.Definition | Out-Null
                            Protect-BcoPwConfigFile -Path $Using:tempPwCfgPath -PwInstallPath $Using:PwInstallPath -Destination $Using:pwCfgPath -Type $Using:Type `
                                                    -Backup -PassThru -Force
                        
                            if (!$Using:SkipDestinationServiceRestart) {
                                Stop-Service -Name 'PWAppSrv' -Force -ErrorAction 'Stop'
                                Start-Service -Name 'PWAppSrv' -ErrorAction 'Stop'
                            }
                        }
                        catch {
                            throw ('Failed to protect file {0}:{1}. Error: {2}' -f 
                                    ($Using:destinationSession).ComputerName,$Using:pwCfgPath,$PSItem.Exception)
                        }
                        finally {
                            if (Test-Path -Path $Using:tempPwCfgPath) {
                                Remove-Item -Path $Using:tempPwCfgPath -Force -ErrorAction 'SilentlyContinue'
                            }
                        }
                    }
                }
                catch {
                    throw $PSItem
                }
                finally {
                    $destinationSession | Remove-PSSession -ErrorAction 'SilentlyContinue'    
                }
            }
        }
        catch {
            throw $PSItem
        }
        finally {
            if ($sourceSession) {
                Invoke-Command -Session $sourceSession -ErrorAction 'Stop' -ScriptBlock {
                    if (Test-Path -Path $Using:decryptedFile.FullName) {
                        Remove-Item -Path $Using:decryptedFile.FullName -Force -ErrorAction 'SilentlyContinue'
                    }
                }
            }
            $sourceSession | Remove-PSSession -ErrorAction 'SilentlyContinue'
        }
    }

    # Do
    if ($Type -eq 'dmskrnl') {
        Sync-BcoPwConfigFile -ComputerName $SourceComputerName -DestinationComputerName $DestinationComputerName -Type 'dmskrnl' `
                -PwInstallPath 'C:\Program Files\Bentley\ProjectWise\' `
                -Credential $Credential `
                #-SkipDestinationServiceRestart    
    }
    elseif ($Type -eq 'dmsafp') {
        Sync-BcoPwConfigFile -ComputerName $SourceComputerName -DestinationComputerName $DestinationComputerName -Type 'dmsafp' `
                -PwInstallPath 'C:\Program Files\Bentley\ProjectWise\' `
                -Credential $Credential `
                -SkipDestinationServiceRestart
    }
    elseif ($Type -eq 'all') {
        Sync-BcoPwConfigFile -ComputerName $SourceComputerName -DestinationComputerName $DestinationComputerName -Type 'dmskrnl' `
                -PwInstallPath 'C:\Program Files\Bentley\ProjectWise\' `
                -Credential $Credential `
                #-SkipDestinationServiceRestart

        Sync-BcoPwConfigFile -ComputerName $SourceComputerName -DestinationComputerName $DestinationComputerName -Type 'dmsafp' `
                -PwInstallPath 'C:\Program Files\Bentley\ProjectWise\' `
                -Credential $Credential `
                -SkipDestinationServiceRestart
    }
}


function Create-PWODBC {

#Parameters used for OF configuration

    Param(
        [Parameter(Mandatory = $true)]
        [string]$PrincipalSQL,
        [Parameter(Mandatory = $true)]
        [String] $MirrorSQL,
        [String[]]$ODBCNAME
    )

$Driver = 'C:\Windows\system32\sqlncli11.dll'

foreach ($name in $ODBCNAME)
{
    $path = "HKLM:\SOFTWARE\ODBC\ODBC.INI\$name"
    if ( -not (Test-Path $path)) {
        $SqlUserName = $name -replace 'db','user'
        Write-Host "ODBC Connection being created for Orchestration Framework db" -ForegroundColor Cyan
        new-item -Path HKLM:\SOFTWARE\ODBC\ODBC.INI -Name $name
        new-itemproperty -path "HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources" -Name $name -PropertyType String -Value 'SQL Server Native Client 11.0'
        new-itemproperty -path HKLM:\SOFTWARE\ODBC\ODBC.INI\$name -Name 'Database' -PropertyType String -Value $name
        new-itemproperty -path HKLM:\SOFTWARE\ODBC\ODBC.INI\$name -Name 'Driver' -PropertyType String -Value $Driver
        new-itemproperty -path HKLM:\SOFTWARE\ODBC\ODBC.INI\$name -Name 'Failover_Partner' -PropertyType String -Value $MirrorSQL
        new-itemproperty -path HKLM:\SOFTWARE\ODBC\ODBC.INI\$name -Name 'LastUser' -PropertyType String -Value $SqlUserName
        new-itemproperty -path HKLM:\SOFTWARE\ODBC\ODBC.INI\$name -Name 'Server' -PropertyType String -Value $PrincipalSQL
    }
    else {
        Write-Host "The Key $path already exists." -ForegroundColor Green}
    }
}


function Meh-PWService{
    ## allows you to stop, start, restart, or get status of a pw service dependent on serverType. 
    ## services are obtained from this csv \\bentleyhosting.com\shares\MAS\Misc\PowerShell_Scripts\Modules\MaSLogin\Artifacts\PWServicesPerServerType.csv (update file for service/server relations)
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$deploymentID,
        [Parameter(Mandatory)]
        [ValidateSet("start","stop","restart","status","startMaintenance","endMaintenance")]
        [string]$action,
        [Parameter(Mandatory)]
        [ValidateSet("app","idx","ics","adm","imb","all")] 
        [string]$serverType
    )
    $servicesPerTypePath = '\\bentleyhosting.com\shares\MAS\Misc\PowerShell_Scripts\Modules\MaSLogin\Artifacts\PWServicesPerServerType.csv'
    if($serverType -eq 'all'){
        $serverList = (Get-ServersInMasDeployment -DeploymentId $deploymentID* -ServerNameType DNSHostName)
        $services = (Import-Csv $servicesPerTypePath | Select-Object -ExpandProperty name)
    }
    else{
        $serverList = (Get-ServersInMasDeployment -DeploymentId $deploymentID*$serverType* -ServerNameType DNSHostName)
        $services = (Import-Csv $servicesPerTypePath | Where-Object ServerType -eq $serverType | Select-Object -ExpandProperty name) 
    }

    Switch($action){
        start {foreach($server in $serverList){
        Get-Service -ComputerName $server -Name $services -ErrorAction SilentlyContinue | Start-Service -Verbose}
        }
        stop{foreach($server in $serverList){
        Get-Service -ComputerName $server -Name $services -ErrorAction SilentlyContinue | Stop-Service -Verbose}
        }
        restart{foreach($server in $serverList){
        Get-Service -ComputerName $server -Name $services -ErrorAction SilentlyContinue | Restart-Service -Verbose}
        }
        status{foreach($server in $serverList){
        Get-Service -ComputerName $server -Name $services -ErrorAction SilentlyContinue | Select-Object Status, Name, DisplayName, StartType, MachineName -Verbose}
        }
        ###Stops the service and disables the StartType###
        ###Set-Service -ServiceName doesn't allow service, service..so I had to put it in a loop foreach service (might slow it down just a tad)###
        startMaintenance{foreach($server in $serverList){
        foreach($service in $services){
            Get-Service -ComputerName $server -Name $service -ErrorAction SilentlyContinue | Stop-Service -Verbose
            Set-Service -ComputerName $server -ServiceName $service -StartupType Disabled -ErrorAction SilentlyContinue -Verbose}
            }
        }
        ###Sets StartType to automatic and starts the service###
        endMaintenance{foreach($server in $serverList){
        foreach($service in $services){
            Set-Service -ComputerName $server -ServiceName $service -StartupType Automatic -ErrorAction SilentlyContinue -Verbose
            Get-Service -ComputerName $server -Name $service -ErrorAction SilentlyContinue | Start-Service -Verbose}
            }
        }
    }
}

function Get-PWService{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$deploymentID,
        [Parameter(Mandatory)] 
        [ValidateSet("app","idx","ics","adm","imb","all")]
        [string]$serverType
    )
    $servicesPerTypePath = '\\bentleyhosting.com\shares\MAS\Misc\PowerShell_Scripts\Modules\MaSLogin\Artifacts\PWServicesPerServerType.csv'
    if($serverType -eq 'all'){
        $serverList = (Get-ServersInMasDeployment -DeploymentId $deploymentID* -ServerNameType DNSHostName)
        $services = (Import-Csv $servicesPerTypePath | Select-Object -ExpandProperty name)
    }
    else{
        $serverList = (Get-ServersInMasDeployment -DeploymentId $deploymentID*$serverType* -ServerNameType DNSHostName)
        $services = (Import-Csv $servicesPerTypePath | Where-Object ServerType -eq $serverType | Select-Object -ExpandProperty name) 
    }
    foreach($server in $serverList){
        Get-Service -ComputerName $server -Name $services -ErrorAction SilentlyContinue | Select-Object Status, Name, DisplayName, StartType, MachineName -Verbose}
}

function Stop-PWService{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$deploymentID,
        [Parameter(Mandatory)] 
        [ValidateSet("app","idx","ics","adm","imb","all")] 
        [string]$serverType,
        [ValidateSet("enable","disable")]
        [string]$startType
    )
    $servicesPerTypePath = '\\bentleyhosting.com\shares\MAS\Misc\PowerShell_Scripts\Modules\MaSLogin\Artifacts\PWServicesPerServerType.csv'
    if($serverType -eq 'all'){
        $serverList = (Get-ServersInMasDeployment -DeploymentId $deploymentID* -ServerNameType DNSHostName)
        $services = (Import-Csv $servicesPerTypePath | Select-Object -ExpandProperty name)
    }
    else{
        $serverList = (Get-ServersInMasDeployment -DeploymentId $deploymentID*$serverType* -ServerNameType DNSHostName)
        $services = (Import-Csv $servicesPerTypePath | Where-Object ServerType -eq $serverType | Select-Object -ExpandProperty name) 
    }
    foreach($server in $serverList){
        if($startType -eq 'enable'){
            foreach($service in $services){
                Set-Service -ComputerName $server -ServiceName $service -StartupType Automatic -ErrorAction SilentlyContinue -Verbose
                Get-Service -ComputerName $server -Name $service -ErrorAction SilentlyContinue | Start-Service -Verbose            
            }
        }
        if($startType -eq 'disable'){
            foreach($service in $services){
                Get-Service -ComputerName $server -Name $service -ErrorAction SilentlyContinue | Stop-Service -Verbose
                Set-Service -ComputerName $server -ServiceName $service -StartupType Disabled -ErrorAction SilentlyContinue -Verbose
            }
       
        }
        else{
            Get-Service -ComputerName $server -Name $services -ErrorAction SilentlyContinue | Stop-Service -Verbose
        }
    }
}

function Start-PWService{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$deploymentID,
        [Parameter(Mandatory)] 
        [ValidateSet("app","idx","ics","adm","imb","all")] 
        [string]$serverType,
        [ValidateSet("enable")]
        [string]$startType
    )
    $servicesPerTypePath = '\\bentleyhosting.com\shares\MAS\Misc\PowerShell_Scripts\Modules\MaSLogin\Artifacts\PWServicesPerServerType.csv'
    if($serverType -eq 'all'){
        $serverList = (Get-ServersInMasDeployment -DeploymentId $deploymentID* -ServerNameType DNSHostName)
        $services = (Import-Csv $servicesPerTypePath | Select-Object -ExpandProperty name)
    }
    else{
        $serverList = (Get-ServersInMasDeployment -DeploymentId $deploymentID*$serverType* -ServerNameType DNSHostName)
        $services = (Import-Csv $servicesPerTypePath | Where-Object ServerType -eq $serverType | Select-Object -ExpandProperty name) 
    }
    foreach($server in $serverList){
        if($startType -eq 'enable'){
            foreach($service in $services){
                Set-Service -ComputerName $server -ServiceName $service -StartupType Automatic -ErrorAction SilentlyContinue -Verbose
                Get-Service -ComputerName $server -Name $service -ErrorAction SilentlyContinue | Start-Service -Verbose            
            }
        }
        else{
            try{
                Get-Service -ComputerName $server -Name $services -ErrorAction SilentlyContinue | Start-Service -ErrorAction Stop
            }
            catch [Microsoft.PowerShell.Commands.ServiceCommandException]{
                Write-Warning "Please use -startType enable. Currently it's disabled and the service will not start."
            }
            catch {
                Write-Host "Unknown catch, please investigate."
            }        
        }
    }
}

function Get-PWICSFilesForComparison
{
    <#
    .Synopsis
       Retrieves Copy of InterPlot files
    .DESCRIPTION
       Retrieves a copy of the three main Interplot files
    .EXAMPLE
	    Get-PWICSFilesForComparison -SourceDeploymentID mottpw04 -TargetDeploymentID -mottpw14
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [string]$SourceDeploymentID,
        [Parameter(Mandatory = $true)]
        [string]$TargetDeploymentID
    )
    
    Begin {

        $TargetPath = 'F:\_MAS_OPs\Migration'
        $InterPlotPath1 = 'c$\Program Files (x86)\Common Files\InterPlot\IPLOT\config'
        $InterPlotPath2 = 'c$\Program Files (x86)\ProjectWise InterPlot Organizer\config'
        $InterPlotFiles = 'ip.cfg','iplot.cfg','iplotsrv.cfg'
        $mcm_userPath = 'c$\Program Files\bentley\projectwise\bin'
        $mcm_userFiles = 'mcm.user.cfg'

        $MasterDeploymentID1 = $SourceDeploymentID.Substring(0,$SourceDeploymentID.length-2)
        $MasterDeploymentID2 = $TargetDeploymentID.Substring(0,$TargetDeploymentID.length-2)

        if ($MasterDeploymentID1 -eq $MasterDeploymentID2) {
                $MasterDeploymentID = $MasterDeploymentID1
            }
        else {
            $ErrorMessage = "Root of deployment IDs do not match [$MasterDeploymentID1 $MasterDeploymentID2]"
            Throw $ErrorMessage
        }

        $SourceICSServerList = Get-ServersInMasDeployment -DeploymentId $SourceDeploymentID -ServerNameType Name | Where-Object {$_ -like "*ics*"}
        if (!$SourceServerList) {
            $ErrorMessage = "No Servers Found in $SourceDeploymentID"
            Throw $ErrorMessage
        }

        $TargetICSServerList = Get-ServersInMasDeployment -DeploymentId $TargetDeploymentID -ServerNameType Name | Where-Object {$_ -like "*ics*"}
        if (!$TargetServerList) {
            $ErrorMessage = "No Servers Found in $TargetDeploymentID"
            Throw $ErrorMessage
        }

        $SourceAPPServerList = Get-ServersInMasDeployment -DeploymentId $SourceDeploymentID -ServerNameType Name | Where-Object {$_ -like "*app*"}
        if (!$SourceServerList) {
            $ErrorMessage = "No Servers Found in $SourceDeploymentID"
            Throw $ErrorMessage
        }

        $TargetAPPServerList = Get-ServersInMasDeployment -DeploymentId $TargetDeploymentID -ServerNameType Name | Where-Object {$_ -like "*app*"}
        if (!$TargetServerList) {
            $ErrorMessage = "No Servers Found in $TargetDeploymentID"
            Throw $ErrorMessage
        }

        if (!(Test-Path -Path $TargetPath\$MasterDeploymentID)) {
            New-Item -Path $TargetPath\$MasterDeploymentID -ItemType 'Directory' -Force | Out-Null
        }

        foreach ($item in $InterPlotFiles) {
            if (!(Test-Path $TargetPath\$MasterDeploymentID\$item)) {
                New-Item -Path $TargetPath\$MasterDeploymentID\$item -ItemType 'Directory' -Force | Out-Null
            }
        }
        foreach ($item in $mcm_userFiles) {
            if (!(Test-Path $TargetPath\$MasterDeploymentID\$item)) {
                New-Item -Path $TargetPath\$MasterDeploymentID\$item -ItemType 'Directory' -Force | Out-Null
            }
        }
    }

    Process {
        ForEach ($Server in $SourceICSServerList) {
            ForEach ($InterplotFile in $InterPlotFiles) {
                $NewInterplotFile = $InterPlotFile -replace "[.]cfg","_$Server.cfg"
                if (Test-Path "\\$Server\$InterPlotPath1\$InterplotFile") {
                    Write-Verbose "Copying \\$Server\$InterPlotPath1\$InterplotFile to $TargetPath\$MasterDeploymentID\$InterplotFile\$NewInterplotFile" -Verbose
                    Copy-Item "\\$Server\$InterPlotPath1\$InterplotFile" "$TargetPath\$MasterDeploymentID\$InterplotFile\$NewInterplotFile" -Force
                }
                if (Test-Path "\\$Server\$InterPlotPath2\$InterplotFile") {
                Write-Verbose "Copying \\$Server\$InterPlotPath1\$InterplotFile to $TargetPath\$MasterDeploymentID\$InterplotFile\$NewInterplotFile" -Verbose
                    Copy-Item "\\$Server\$InterPlotPath2\$InterplotFile" "$TargetPath\$MasterDeploymentID\$InterplotFile\$NewInterplotFile" -Force
                }
            }
        }
        ForEach ($Server in $TargetICSServerList) {
            ForEach ($InterplotFile in $InterPlotFiles) {
                $NewInterplotFile = $InterPlotFile -replace "[.]cfg","_$Server.cfg"
                if (Test-Path "\\$Server\$InterPlotPath1\$InterplotFile") {
                    Write-Verbose "Copying \\$Server\$InterPlotPath1\$InterplotFile to $TargetPath\$MasterDeploymentID\$InterplotFile\$NewInterplotFile" -Verbose
                    Copy-Item "\\$Server\$InterPlotPath1\$InterplotFile" "$TargetPath\$MasterDeploymentID\$InterplotFile\$NewInterplotFile" -Force
                }
                if (Test-Path "\\$Server\$InterPlotPath2\$InterplotFile") {
                Write-Verbose "Copying \\$Server\$InterPlotPath1\$InterplotFile to $TargetPath\$MasterDeploymentID\$InterplotFile\$NewInterplotFile" -Verbose
                    Copy-Item "\\$Server\$InterPlotPath2\$InterplotFile" "$TargetPath\$MasterDeploymentID\$InterplotFile\$NewInterplotFile" -Force
                }
            }
        }

        ForEach ($Server in $SourceAPPServerList) {
            ForEach ($mcm_userFile in $mcm_userFiles) {
                $NewMCM_UserFile = $mcm_userFile -replace "[.]cfg","_$Server.cfg"
                if (Test-Path "\\$Server\$mcm_userPath\$mcm_userFile") {
                Write-Verbose "Copying \\$Server\$mcm_userPath\$mcm_userFile to $TargetPath\$MasterDeploymentID\$mcm_userFile\$NewMCM_UserFile" -Verbose
                    Copy-Item "\\$Server\$mcm_userPath\$mcm_userFile" "$TargetPath\$MasterDeploymentID\$mcm_userFile\$NewMCM_UserFile" -Force
                }
            }
        }
        ForEach ($Server in $TargetAPPServerList) {
            ForEach ($mcm_userFile in $mcm_userFiles) {
                $NewMCM_UserFile = $mcm_userFile -replace "[.]cfg","_$Server.cfg"
                if (Test-Path "\\$Server\$mcm_userPath\$mcm_userFile") {
                Write-Verbose "Copying \\$Server\$mcm_userPath\$mcm_userFile to $TargetPath\$MasterDeploymentID\$mcm_userFile\$NewMCM_UserFile" -Verbose
                    Copy-Item "\\$Server\$mcm_userPath\$mcm_userFile" "$TargetPath\$MasterDeploymentID\$mcm_userFile\$NewMCM_UserFile" -Force
                }
            }
        }
    }

    End { 
        Get-ChildItem "$TargetPath\$MasterDeploymentID" -Recurse | select fullname
        explorer "$TargetPath\$MasterDeploymentID"

        foreach ($interplotfile in $InterPlotFiles) {
            $filePrefix = $interplotfile -replace ".cfg",""

            $File1 = "$TargetPath\$MasterDeploymentID\$fileprefix" + "_$SourceDeploymentID" + "ics01.cfg"
            $File2 = "$TargetPath\$MasterDeploymentID\$fileprefix" + "_$TargetDeploymentID" + "ics01.cfg"

            #& 'C:\Program Files (x86)\Notepad++\notepad++.exe' -multiInst $file1 $file2
        }
    }
}

function Add-PW_DocProc_Exclusion_List {
    [CmdletBinding()]
    param(
        [parameter(Mandatory=$True,ValueFromPipeline=$True)]
        [string[]]$Datasource
    )

    BEGIN {
        $AllExtensions = Import-Csv \\bentleyhosting.com\shares\mas\Misc\PowerShell_Scripts\DB_Migrations\db_scripts\PW_DocProc_Exclusion_List.csv
    }
    PROCESS {
        foreach ($ds in $Datasource) {
            $connect = Connect-PWdatasource $ds
            if ($connect) {
                    $Thumb = Get-PWIndexServerFileExtensionFilters -Thumbnail
                    $Extensions = $AllExtensions | where ProcessorType -eq 'Thumbnail'
                    foreach ($Extension in $Extensions) {
                        Write-Verbose "Checking extension for Thumbnail: $($Extension.FilteredExtension)"
                        if ($Extension.FilteredExtension -notin $Thumb.FilteredExtension) {
                            write-verbose "Found a missing extension Thumbnail: $($Extension.FilteredExtension)"
                            Add-PWIndexServerFileExtensionFilter -Thumbnail -FileExtensions $Extension.FilteredExtension  
                        }
                    }

                    $FTR = Get-PWIndexServerFileExtensionFilters -FullText
                    $Extensions = $AllExtensions | where ProcessorType -eq 'Full Text'
                    foreach ($Extension in $Extensions) {
                        Write-Verbose "Checking extension for Full Text: $($Extension.FilteredExtension)"
                        if ($Extension.FilteredExtension -notin $Ftr.FilteredExtension) {
                            write-verbose "Found a missing extension for Full Text: $($Extension.FilteredExtension)"
                            Add-PWIndexServerFileExtensionFilter -FullText -FileExtensions $Extension.FilteredExtension  
                        }
                    }

                    $FileProp = Get-PWIndexServerFileExtensionFilters -FileProperties
                    $Extensions = $AllExtensions | where ProcessorType -eq 'File Properties'
                    foreach ($Extension in $Extensions) {
                        Write-Verbose "Checking extension for FTR: $($Extension.FilteredExtension)"
                        if ($Extension.FilteredExtension -notin $Fileprop.FilteredExtension) {
                            write-verbose "Found a missing extension for File Properties: $($Extension.FilteredExtension)"
                            Add-PWIndexServerFileExtensionFilter -FileProperties -FileExtensions $Extension.FilteredExtension  
                        }
                    }
            }
            else {
                Write-Error "Unable to log into datasource: $ds" -ErrorAction Continue
            }
        }
    }
}

function Get-PWCORSFromWSG {
    <#
    .Synopsis
       Retrieves All CORS items from WSG
    .DESCRIPTION
       Retrieves a list of CORS items split into individual records
    .EXAMPLE
	    Get-PWCORSFromWSG -DeploymentID mottpw04, mottpw06 -ServerNameType DNSHostName
    .EXAMPLE
	    Get-PWCORSFromWSG -DeploymentID mottpw04, mottpw06
    .EXAMPLE
	    Get-PWCORSFromWSG -DeploymentID mottpw04, mottpw06 -ServerNameType Name
    .EXAMPLE
        $deploymentID = 'mottpw04'
        $deploymentID | Get-PWCORSFromWSG   
    #>

    Param (
        [Parameter(
        Position = 0, 
        Mandatory = $true, 
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true)
        ]
        [string[]]$DeploymentID,

        [ValidateSet("Name", "DNSHostName")]
        [String] $ServerNameType="DNSHostName"
    )

    BEGIN {
        $wsgpath = 'c$\www'
        $corskey = 'Wsg.Security.AccessControlAllowOrigin'
        $allcors = @()
    }

    PROCESS {
        foreach ($deploy in $deploymentID) {
            $server = Get-ServersInMasDeployment -DeploymentId "$($deploy)app*" -ServerNameType $ServerNameType
            foreach ($s in $server) {
                Write-Verbose "Getting CORS content from $s"
                $file = Get-ChildItem \\$s\c$\www | where name -match 'ws'
                $content = Get-Content  \\$s\$wsgpath\$($file.Name)\ws\web.config
                $corscontent = $content | select-string "$corskey" -SimpleMatch
                foreach ($cors in $corscontent) {
                    $cors = ($cors -replace '<add key="Wsg.Security.AccessControlAllowOrigin" value="','').Trim()
                    $cors = ($cors -replace '/>','').trim()
                    $cors = ($cors -replace '"','').trim()
                    $cors = $cors -replace ', ',','
                    $corsSplit = $cors -split ","

                    foreach ($IndividualCors in $corsSplit) {
                        $object = @{
                            Server = $s
                            CORSItem = $IndividualCors

                        }
                        $allcors += New-Object PSOBject -Property $object
                    }
                }
            }
        }
    }

    END {
        $allcors
    }
}

function Install-PWPS_DAB {
    [CmdletBinding()]
    Param (
        [string[]]$Computername = (Invoke-Expression -Command 'hostname')
    )
    BEGIN {

        $cred = Get-CredentialObjectFromFile -ErrorAction SilentlyContinue

        if (!$cred) {
               Write-Warning "No saved credentials found"
               #Write-Information "Please run Save-CredentialObjectdToFile"
               Save-CredentialObjectToFile
               $cred = Get-CredentialObjectFromFile -ErrorAction Stop
        }

        $x = Find-Module -Name pwps_dab
    }
    PROCESS {
        $Results = Invoke-Command -ComputerName $ComputerName -Credential $cred -ConfigurationName microsoft.powershell -ArgumentList $x -ScriptBlock `
        {
            param($PWPS_DAB_Gallery)
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $PWPS_DAB_Local = get-module -name pwps_dab -ListAvailable

            write-information $env:COMPUTERNAME

            if ($PWPS_DAB_Local){
                if (($PWPS_DAB_Gallery.Version -ne $PWPS_DAB_Local.Version)) {
                    Uninstall-module pwps_dab -AllVersions -Force
                    Install-module pwps_dab -AllowClobber -SkipPublisherCheck -Force
                    #Show-PWPS_DABChangeLog
                }
            }
            Else {
                Install-module pwps_dab -AllowClobber -SkipPublisherCheck -Force
                #Show-PWPS_DABChangeLog
            }
        }
    }
    END {
        $Results
    }
}