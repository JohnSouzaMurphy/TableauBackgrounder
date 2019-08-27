## Author: John Souza Murphy
## Email: jsouzamurphy@tableau.com
## Version: 1.0
## Date: 27/08/2019
## Description: This is a simple Powershell Module which allows us to list and kill Backgrounder jobs using the REST API.
## Tested: Only tested with Tableau Server 2019.2 running on Powershell version 5.1 so far.
## Expect to work with Tableau Server versions 2018.2 and newer.

## Usage: 
## 'New-APILogin' must be run first for authentication.
## 'New-APILogin -Credential [username] -TableauServer [servername] -SSL [Yes/No] -Version [Tableau Server Version e.g. 2019.1]'
## 'Get-BGProcess -Help' for usage instructions.
## 'Kill-BGProcess -Help' for usage instructions.


# Informational Message after importing module.

Write-Host "You must sign in to your Tableau Server using 'New-APILogin' before working with Backgrounder processes." -ForegroundColor Yellow
Write-Host "Use 'New-APILogin -Help' for usage instructions." -ForegroundColor Yellow


# New-APILogin takes care of the authentication against the REST API.

Function global:New-APILogin {


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


            # Providing Usage information on New-APILogin
            if ($Help){
            
            Write-Host "Usage: " -ForegroundColor Yellow
            Write-Host "'New-APILogin -Credential [username] -TableauServer [servername] -SSL [Yes/No] -Version [Tableau Server Version e.g. 2019.1]'" -ForegroundColor Yellow
            Write-Host "All above parameters are mandatory." -ForegroundColor Yellow
            
            } else { 


            # Setting up Credential and Server URI variables

            $dMain = $Credential.GetNetworkCredential().Domain
            $Username = $Credential.GetNetworkCredential().UserName
            $Password = $Credential.GetNetworkCredential().Password
            if($SSL -eq "Yes"){
                $prefix = "https://"
            } elseif ($SSL -eq "No"){
                $prefix = "http://"
            }

            if ($Version -eq "2018.2"){
            $API = "3.1"
            } elseif ($Version -eq "2018.3"){
            $API = "3.2"
            } elseif ($Version -eq "2019.1"){
            $API = "3.3"
            } elseif ($Version -eq "2019.2"){
            $API = "3.4"
            } elseif ($Version -eq "2019.3"){
            $API = "3.4"
            }

            $TServer = $prefix + $TableauServer

            # Create body request for login/authentication

            $loginbody = (’<tsRequest>
             <credentials name=“’ + $Username + ’” password=“’+ $Password + ’” >
               <site contentUrl=“” />
             </credentials>
            </tsRequest>’)

            # Compile sign in URI

            $signInURI = "$TServer/api/$API/auth/signin"

            # Sending Authentication Request
            $response = Invoke-RestMethod -Uri $signInURI -Body $loginbody -Method Post
            # Store authentication token and details for continued use

            $authToken = $response.tsResponse.credentials.token
            $global:siteID = $response.tsResponse.credentials.site.id
            $myUserID = $response.tsResponse.credentials.user.id

            # set up header fields with auth token
            $global:headers = New-Object “System.Collections.Generic.Dictionary[[String],[String]]”

            # add X-Tableau-Auth header with our auth token
            $global:headers.Add(“X-Tableau-Auth”, $authToken)

            $global:BaseURI = "$TServer/api/$API/sites/"

            Write-Host "You are now signed in." -ForegroundColor Green
            Write-Host "Run 'Get-BGProcess -Help' to see options." -ForegroundColor Green
            Write-Host "Run 'Kill-BGProcess -Help' to see options." -ForegroundColor Green

 }
}


Function global:Get-BGProcess {

        
        # Declaring Parameters
        [CmdletBinding()]

        param(
            [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [switch]$ShowFailed,
            [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [switch]$OnlyActive,
            [Parameter(Mandatory=$false, ValueFromPipelineByPropertyName=$true)]
            [switch]$Help
            )

            # Showing usage information on Get-BGProcess
            if ($Help){
            
            Write-Host "Usage: " -ForegroundColor Yellow
            Write-Host "'Get-BGProcess' alone will display all Backgrounder jobs, except for failed jobs." -ForegroundColor Yellow
            Write-Host "'Get-BGProcess -ShowFailed' will display all Backgrounder jobs, including failed jobs." -ForegroundColor Yellow
            Write-Host "'Get-BGProcess -OnlyActive' will display only Backgrounder jobs which are running i.e. not failed or cancelled." -ForegroundColor Yellow
            } else {

            # Handling error if both ShowFailed and OnlyActive are specified in the command. There is a conflict.
            if ($ShowFailed -and $OnlyActive){
            
            throw "You can not use both the -ShowFailed and -OnlyActive switches in the same command."

            } else {

            $Method = "GET"
            $Resource = "jobs"

            $requestURI = $BaseURI + $SiteID + "/" + $Resource
            
            # Storing list of all backgrounder jobs
            $Results = Invoke-RestMethod -Uri $requestURI -Headers $headers -Method $Method

            # ShowFailed switch execution
            if ($ShowFailed){

            $Results.tsResponse.backgroundJobs.backgroundJob
            
            } 
            # OnlyActive switch execution
            elseif ($OnlyActive){

            $anyActive = $Results.tsResponse.backgroundJobs.backgroundJob | ?{$_.status -ne "Failed" -and $_.status -ne "Cancelled"}
            
                if ($anyActive -eq $null){
                    Write-Host "There are currently no active Backgrounder jobs running." -ForegroundColor Green
                } else {
                
                $Results.tsResponse.backgroundJobs.backgroundJob | ?{$_.status -ne "Failed" -and $_.status -ne "Cancelled"}
                
                }

            # No Switch Get-BGProcess execution
            } else {
            
            $Results.tsResponse.backgroundJobs.backgroundJob | ?{$_.status -ne "Failed"}

            }

            }

            }
            

}

   
Function global:Kill-BGProcess {
             

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
        elseif ($JobID) {

            $jobExists = Get-BGProcess -OnlyActive | ?{$_.id -like $JobID}
            if ($jobExists -ne $null){

         $Method = "PUT"
         $Resource = "jobs"
         $requestURI = $BaseURI + $SiteID + "/" + $Resource + "/" + $JobID
         $Results = Invoke-RestMethod -Uri $requestURI -Headers $headers -Method $Method
         Write-Host "Job with ID $JobID has been cancelled." -ForegroundColor DarkYellow
         $Results.tsResponse.backgroundJobs.backgroundJob

         } 
         else {
         
         Write-Host "There are no active Backgrounder jobs with id: $JobID." -ForegroundColor DarkYellow

         }

        # No options execution - displays interactive list of jobs running and user can specify using just a number option.
        } else
        
        
        {

            $Method = "PUT"
            $Resource = "jobs"
            $jobIDs = Get-BGProcess | ?{$_.status -ne "Cancelled"} | Select id
            $numOfJobs = $jobIDs.id
            $maxjobs = $numOfJobs.Count

            if($maxjobs -gt 0){
            
            $i = 1
            ForEach ($id in $jobIDs){
            Write-Host $i" = " $id.id
            $x = $i
            New-Variable -Name $x -Value $id.id -Option AllScope
            $i++
            }

            $option = Read-Host "Which job would you like to kill?"

                        
            For ($i=1; $i -le $maxjobs; $i++){
                if($option -eq $i){
                    $killJob = Get-Variable -ValueOnly $i
                }
            }

            $requestURI = $BaseURI + $SiteID + "/" + $Resource + "/" + $killJob

            $Results = Invoke-RestMethod -Uri $requestURI -Headers $headers -Method $Method
            Write-Host "Job with ID $killJob has been cancelled." -ForegroundColor DarkYellow

            $Results.tsResponse.backgroundJobs.backgroundJob

            $maxjobs = ""
            } elseif ($maxjobs -le 0){
            Write-Host "There are no active Backgrounder jobs to kill." -ForegroundColor Green
            }

        }
}

# Exporting Module Members.
Export-ModuleMember -Function New-APILogin
Export-ModuleMember -Function Kill-BGProcess
Export-ModuleMember -Function Get-BGProcess
