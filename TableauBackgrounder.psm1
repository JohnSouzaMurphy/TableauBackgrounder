## Author: John Souza Murphy
## Email: jsouzamurphy@tableau.com
## Version: 1.0
## Date: 21/10/2019
## Description: "TableauBackgrounder" is a simple Powershell Module which allows you to list and terminate/kill Backgrounder jobs using the REST API.
## Dependencies: Works with Tableau Server versions 2018.2 and later. Requires Powershell version 3.0 to run.

## Usage: 
## 'New-TableauLogin' must be run first for authentication.
## 'New-TableauLogin -Credential [username] -TableauServer [servername] -SSL [Yes/No] -Version [Tableau Server Version e.g. 2019.1]'
## 'Get-BGProcess -Help' for usage instructions.
## 'Kill-BGProcess -Help' for usage instructions.


# Instructional Message following "import-module"

Write-Host "You must sign in to your Tableau Server using 'New-TableauLogin' before working with Backgrounder processes." -ForegroundColor Yellow
Write-Host "Use 'New-TableauLogin -Help' for usage instructions." -ForegroundColor Yellow


# New-TableauLogin takes care of the authentication against the REST API.

Function global:New-TableauLogin {

# Objectives of Function: New-TableauLogin
# 1) Build Sign-in request URI - http[s]://[servernameorip]/api/[api-version]/auth/signin
# 2) Collect and transform secure credentials to passable variables
# 3) Authenticate and store authentication token for later use


    # Declaring Parameters - mandatory not set to True, but they are all required. This was to facilitate the -Help option.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [PSCredential]$Credential = [System.Management.Automation.PSCredential]::Empty,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$TableauServer,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Yes","No")]
        [string]$SSL,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("2018.2","2018.3","2019.1","2019.2","2019.3")]
        [Alias("Tableau Server Version")]
        [string]$Version,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [switch]$Help
        )

    # Providing usage information on New-TableauLogin
    if ($Help){           
        Write-Host "Usage: " -ForegroundColor Yellow
        Write-Host "'New-TableauLogin -Credential [username] -TableauServer [servername] -SSL [Yes/No] -Version [Tableau Server Version e.g. 2019.1]'" -ForegroundColor Yellow
        Write-Host "All above parameters are mandatory." -ForegroundColor Yellow
              } 
    else { 
        # Setting up Credential and Server URI variables
        $Username = $Credential.GetNetworkCredential().UserName
        $Password = $Credential.GetNetworkCredential().Password
        # Build Request URI Scheme / prefix variable.
        if ($SSL -eq "Yes"){
            $scheme = "https://"
                           } 
        elseif ($SSL -eq "No"){
            $scheme = "http://"
                              }

        # Build Request URI Path / Determine API Version.
        if ($Version -eq "2018.2"){
            $API = "3.1"
                                  } 
        elseif ($Version -eq "2018.3"){
            $API = "3.2"
                                      } 
        elseif ($Version -eq "2019.1"){
            $API = "3.3"
                                      } 
        elseif ($Version -eq "2019.2"){
            $API = "3.4"
                                      } 
        elseif ($Version -eq "2019.3"){
            $API = "3.4"
                                      }

        # Begin to compile sign-in Request URI
        $TServer = $scheme + $TableauServer
        # Complete sign-in Request URI
        $signInURI = "$TServer/api/$API/auth/signin"
        # Create body request for login/authentication
        # https://help.tableau.com/current/api/rest_api/en-us/REST/rest_api_concepts_auth.htm 
        $loginbody = (’<tsRequest>
                        <credentials name=“’ + $Username + ’” password=“’+ $Password + ’” >
                            <site contentUrl=“” />
                        </credentials>
                       </tsRequest>’)

        # Sending Authentication Request
        try {
            $response = Invoke-RestMethod -Uri $signInURI -Body $loginbody -Method Post
            }
        catch {
              }

        # Check if sign-in succesful
        if ($response){
            # Store authentication token and details for continued use
            $authToken = $response.tsResponse.credentials.token
            $global:siteID = $response.tsResponse.credentials.site.id
            $myUserID = $response.tsResponse.credentials.user.id
            # set up header fields with auth token
            $global:headers = New-Object “System.Collections.Generic.Dictionary[[String],[String]]”
            # add X-Tableau-Auth header with our auth token
            $global:headers.Add(“X-Tableau-Auth”, $authToken)
            # Declare the Base URI of all REST API requests inside a variable for repeated use.
            $global:BaseURI = "$TServer/api/$API/sites/"
            Write-Host "You are now signed in." -ForegroundColor Green
            Write-Host "Run 'Get-BGProcess -Help' to see options." -ForegroundColor Green
            Write-Host "Run 'Kill-BGProcess -Help' to see options." -ForegroundColor Green
                      }
        else {
            # Sign in unsuccessful 
            Write-Host "Unable to connect to your Tableau Server: $TableauServer." -ForegroundColor Red
            Write-Host "Please check that the Server Name/IP is correct and that the server is online." -ForegroundColor Red
            Write-Host "Also, make sure that your username and password are correct." -ForegroundColor Red
             }
        }
}

# Get-BGProcess lists backgrounder jobs found on Tableau Server

Function global:Get-BGProcess {

# 1) Build request URI - http[s]://[servernameorip]/api/[api-version]/sites/[siteID]/[jobs]
# 2) Request and store list of Backgrounder Jobs
# 3) Display list of backgrounder jobs with logic to show Only Active or All jobs
        
    # Declaring Parameters
    [CmdletBinding()]
    param(
        # AsForm parameter not required by end-user. It is there to allow subsequent calls of this function to be used elsewhere.
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [switch]$DisplayAsTable,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [switch]$OnlyActive,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [switch]$Help
         )

    # Showing usage information on Get-BGProcess
    if ($Help){
        Write-Host "Usage: " -ForegroundColor Yellow
        Write-Host "'Get-BGProcess' will display all Backgrounder jobs found on Tableau Server." -ForegroundColor Yellow
        Write-Host "'Get-BGProcess -OnlyActive' will display only any Backgrounder jobs that are currently active." -ForegroundColor Yellow
              } 

    else {
        $Method = "GET"
        $Resource = "jobs"
        # Build Request URI for jobs
        $requestURI = $BaseURI + $SiteID + "/" + $Resource
        # Storing list of all backgrounder jobs
        $Results = Invoke-RestMethod -Uri $requestURI -Headers $headers -Method $Method
        # List only jobs which are active

        if ($OnlyActive){
            # Declare variable to determine whether or not there are any active jobs running.
            $anyActive = $Results.tsResponse.backgroundJobs.backgroundJob | ?{$_.status -ne "Failed" -and $_.status -ne "Cancelled" -and $_.status -ne "Success"}
                if ($anyActive -eq $null){
                    Write-Host "There are currently no active Backgrounder jobs running." -ForegroundColor Green
                                         }
                else {
                    if ($DisplayAsTable){
                        $Results.tsResponse.backgroundJobs.backgroundJob | ?{$_.status -ne "Failed" -and $_.status -ne "Cancelled" -and $_.status -ne "Success"} | Format-Table -AutoSize
                                } 
                    else {
                    $Results.tsResponse.backgroundJobs.backgroundJob | ?{$_.status -ne "Failed" -and $_.status -ne "Cancelled" -and $_.status -ne "Success"} 
                         }
                     }
                        }
        else {
            if ($DisplayAsTable){
                $Results.tsResponse.backgroundJobs.backgroundJob | Format-Table -AutoSize 
                        } 
            else {
                $Results.tsResponse.backgroundJobs.backgroundJob 
                 }
             }
         }
}


Function global:Kill-BGProcess {
        
# 1) Build request URI - http[s]://[servernameorip]/api/[api-version]/sites/[siteID]/[jobs]/[jobid]
# 2) Provide interactive program for user to select and terminate Backgrounder Job
# 3) Send Cancel_Job request to specified JobID
# 4) Provide option to specify job id directly from the command line as alternative 

# Declaring Parameters

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [switch]$Help,
        [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
        [string]$JobID
         )

    # Usage information on Kill-BGProcess
    if ($Help){
        Write-Host "Usage:" -ForegroundColor Yellow
        Write-Host "'Kill-BGProcess' will present you with a list of active Backgrounder jobs." -ForegroundColor Yellow
        Write-Host "Each number listed correlates to the Job ID beside it. Type the number of the job you want to cancel and press Enter." -ForegroundColor Yellow
              }
        
    # -JobID switch execution - if User already knows Job ID, it can be specified directly from command line using this switch.
    elseif ($JobID){
        # Check if the job id provided by the end user matches any jobs.
        $jobExists = Get-BGProcess -OnlyActive | ?{$_.id -like $JobID}
            if ($jobExists -ne $null){
                $Method = "PUT"
                $Resource = "jobs"
                $requestURI = $BaseURI + $SiteID + "/" + $Resource + "/" + $JobID
                $Results = Invoke-RestMethod -Uri $requestURI -Headers $headers -Method $Method
                Write-Host "Job with ID $killJob has been cancelled." -ForegroundColor DarkYellow
                $Results.tsResponse.backgroundJobs.backgroundJob
                                     } 
            else {
                Write-Host "There are no active Backgrounder jobs with id: $JobID." -ForegroundColor DarkYellow
                 }

        # No options execution - displays interactive list of jobs running and user can specify using just a number option.
                    } 
    else {
        $Method = "PUT"
        $Resource = "jobs"
        # Store a list of active backgrounder job ID's
        $jobIDs = Get-BGProcess | ?{$_.status -ne "Cancelled" -and $_.status -ne "Failed" -and $_.status -ne "Success"} | Select id
        # $jobIDs = Get-BGProcess -AsForm -OnlyActive | Select id
        $jIDs = $jobIDs.id
        $maxjobs = $jIDs.Count

        if($maxjobs -gt 0){
            # create $i variable in order to name new variables within loop.
            $i = 1
            ForEach ($id in $jobIDs){
                Write-Host $i" = " $id.id
                $x = $i
                # Create variable with a name that is equal to the current iteration (e.g. 1, 2, 3 etc.)
                # Store the job id of the current iteration inside the variable to be called upon later by the end user.
                New-Variable -Name $x -Value $id.id -Option AllScope
                $i++
                                    }

            # Request input from user
            $option = Read-Host "Which job would you like to kill?"
            # Check the Users option against the list of jobs and take the value of the matching job variable (the job id) and store it in a new variable called killJob

            For ($i=1; $i -le $maxjobs; $i++){
                if($option -eq $i){
                    $killJob = Get-Variable -ValueOnly $i
                                  }
                                             }

            # Build Request URI to terminate (Cancel_Job) the specific backgrounder job.
            $requestURI = $BaseURI + $SiteID + "/" + $Resource + "/" + $killJob
            $Results = Invoke-RestMethod -Uri $requestURI -Headers $headers -Method $Method
            Write-Host "Job with ID $killJob has been cancelled." -ForegroundColor DarkYellow
            $Results.tsResponse.backgroundJobs.backgroundJob
            $maxjobs = ""
                           }

        elseif ($maxjobs -le 0){
            Write-Host "There are no active Backgrounder jobs to kill." -ForegroundColor Green
                               }
         }
}

# Exporting Module Members.
Export-ModuleMember -Function New-TableauLogin
Export-ModuleMember -Function Kill-BGProcess
Export-ModuleMember -Function Get-BGProcess
