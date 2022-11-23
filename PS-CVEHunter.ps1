<#
.SYNOPSIS
The script seaches disks for given filenames or partly filenames
and returns results. This is a tool to help hunt down CVEs

.DESCRIPTION
The script seaches disks for given filenames or partly filenames
and returns results. This is a tool to help hunt down CVEs

.PARAMETER maxCores
The numbers of cores to be used when scanning the drives to get
all files and dirs

.PARAMETER DrivesExclude
The letter of a drive to exclude from scanning
e.g. for single value 
"C"
e.g. for multiple values
"C,D"

.PARAMETER needles
Search terms. It can be provided in form of a string.
e.g. for single value
"a.exe"
e.g for multiple values
"a.exe,b.msi,c.log"

.PARAMETER GCValue
The Garbage Collector value to be use for gdu
Read more here https://tip.golang.org/doc/gc-guide
If you don't know what you are doing don't use this

.PARAMETER OutputFilePath
If this property is populated then the results will also
be outputed to a file to the given file path. 
If not OutputFilePath is used the results will be returned in
the stdout or terminal.
e.g. 
"C:\results.txt"

.PARAMETER Verbose
If verbose is used some more info will be given in the output
such as time it takes to get gdu results, to convert them and 
find results.

.OUTPUTS
Filepaths of searched files

.EXAMPLE
Search for a.exe, with 16cores, provide more info, output the results to a txt file and exclude disk C
.\PS-CVEHunter.ps1 -needles "a.exe" -maxCores 16 -Verbose -OutputFilePath "C:\1.txt" -DrivesExclude "C"

Search for both a.exe and b.log, with default number of cores (max 8), without garbace gollector, on all disks
.\PS-CVEHunter.ps1 -needles "a.exe,b.log"

.LINK
Links to further documentation.

.NOTES
Detail on what the script does, if this is needed.
#>
[CmdletBinding()]
Param(
     
[int]$maxCores = 8,
[string]$DrivesExclude,
[Parameter(Mandatory=$true)]
[string]$needles,
[int]$GCValue,
[string]$OutputFilePath
)

if ($VerbosePreference -eq $true)
{
    $VerbosePreference = "continue"
} 
[string[]]$needles = $needles -split ","
[string[]]$DrivesExclude = $DrivesExclude -split ","

function Get-PhysicalDrives
{
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]
        $DrivesExclude
    )

    # Examples: 
    # Get-PhysicalDrives
    # DriveLetter FriendlyName FileSystemType DriveType HealthStatus OperationalStatus SizeRemaining      Size
    # ----------- ------------ -------------- --------- ------------ ----------------- -------------      ----
    # D           DATA         NTFS           Fixed     Healthy      OK                     59.29 GB 915.63 GB
    # C                        NTFS           Fixed     Healthy      OK                     11.52 GB  475.7 GB
    #
    # Get-PhysicalDrives -DrivesExclude "C","D" 
    # Returns $null
    #
    # Get-PhysicalDrives -DrivesExclude "C"
    # 
    # DriveLetter FriendlyName FileSystemType DriveType HealthStatus OperationalStatus SizeRemaining      Size
    # ----------- ------------ -------------- --------- ------------ ----------------- -------------      ----
    # D           DATA         NTFS           Fixed     Healthy      OK                     59.29 GB 915.63 GB
    $drives = Get-Volume | Where {$_.DriveLetter -ne $null -and $_.FileSystemType -eq "NTFS"}
    $drives= $drives | Where {$_.DriveLetter -notin $DrivesExclude} | Sort-Object DriveLetter
    return $drives
}

function Get-GDUPath
{
      <#
    .SYNOPSIS
       This function will return the gdu executable path.
       The gdu executable should in the same folder as the script.

    .INPUTS
        None

    .OUTPUTS
       Fullpath of the gdu executable

    .EXAMPLE
        Get-GDUPath

    #>
    return (Get-ChildItem $PSScriptRoot\* -Include "*gdu*.exe" | Select -ExpandProperty FullName)
}



function  ConvertTo-FullPath {
      <#
    .SYNOPSIS
        This function gets the PsCustomObject that has been created from the 
        json outputed from GDU and restructures the full path of a file.

    .DESCRIPTION
        This function calls itself when a Array has been found within the JSON
        to restructure the fullpath of files from within the PSCustomObject that
        has been created via the json created from GDU. 

    .PARAMETER data
        This the part of the pscustomobject array that provides the data that are
        required to reconstruct the full path.

    .PARAMETER path
        Used from the function itself to reconstruct the fullpath.

    .INPUTS
        GDUJson[3] and path as an empty string.

    .OUTPUTS
        None

    .EXAMPLE
        ConvertTo-FullPath -data $data[3] -path ''

    .LINK
       see https://github.com/dundee/gdu/issues/184


    #>
    
    param( 
        $data,
        [string]$path)

    
    if (-not ([string]::IsNullOrEmpty($path))) {
        $path = "$($path)\$($data[0].Name)" 
    }
    else {
        $path = "$($path)$($data[0].Name)" 
    }
         
    foreach ($item in ($data | Select -Skip 1) ) {
        if ($item.GetType().BaseType.Name -eq "Array") {
            ConvertTo-FullPath -data $item -path $path
        }
        else {
            $pathLast = "$($path)\$($item.name)"
        }

        [void]$global:jsonresults.Add($pathLast)   
    }    



}

function Get-FullPathInitiator
{
      <#
    .SYNOPSIS
        Helper function that calls Get-Fullpath

    .DESCRIPTION
        This function calls Get-Fullpath to reconstruct the fullpaths of files
    
    .PARAMETER jsondata
        The json data exported from gdu

    .INPUTS
        The json data exported from gdu

    .OUTPUTS
        Arraylist of fullpaths of files.

    .EXAMPLE
        Get-FullPathInitiator -jsondata $jsondata

    .LINK
       see https://github.com/dundee/gdu/issues/184

    #>
   param(
    $jsondata
   )

   $data = $jsondata  
 
    ConvertTo-FullPath -data $data[3] -path ''
  
   return $global:jsonresults
}

function Invoke-GDUPath
{
    <#
    .SYNOPSIS
        This function runs the gdu

    .DESCRIPTION
        This function runs the gdu with all its arguments
    
    .PARAMETER gdupath
        The location of the gdu executable. The path is provided
        by Get-GDUPath function

    .PARAMETER drive
        The drive that will be scanned e.g. C D

    .PARAMETER maxcores
        The maximum cpu cores to be used by gdu when
        scanning the drive. The default suggested value
        from gdu creator is 8.
    
    .PARAMETER GCValue
        The aggressiveness and intensity of GO Garbace Gollector
        Read more here  https://tip.golang.org/doc/gc-guide
        If you don't know what you are doing don't use this 
        parameter

    .INPUTS
        - Gdu executable path
        - Drive letter to be scanned
        - Max Cores
        - Garbage Collector intensity

    .OUTPUTS
        Json files that contains dirs and files

    .EXAMPLE
        Invoke-GDUPath -gdupath c:\gdu.exe -drive "C" -maxCores 16


    #>
    param(
        [string]$gduPath,
        [string]$drive,
        [int]$maxCores,
        [int]$GCValue
    )
    $driveFull = "$($drive):\"
    $arguments = "$driveFull -o- -p -m $maxCores"
    $output = $null
    $psi = New-object System.Diagnostics.ProcessStartInfo 
    $psi.CreateNoWindow = $true 
    $psi.UseShellExecute = $false 
    $psi.RedirectStandardOutput = $true 
    $psi.RedirectStandardError = $true 
    #$psi.FileName = $gduPath 
    if ($GCValue)
    {
        $psi.EnvironmentVariables["GOGC"]=$GCValue
        $arguments = "$driveFull -g -o- -p -m $maxCores"
    }
    $psi.FileName = $gduPath
    $psi.Arguments = $arguments
    $process = New-Object System.Diagnostics.Process 
    $process.StartInfo = $psi 
    [void]$process.Start()
    $output = ($process.StandardOutput.ReadToEnd() | ConvertFrom-JSON)
    $process.WaitForExit() 

    return $output
}

function Get-Needles
{
    <#
    .SYNOPSIS
       The functions uses LINQ to scan fast through the fullpaths and scan via regex for results  

    .DESCRIPTION
        This functions will search the output of ConvertTo-Fullpath to find the required search keywords (needle)
        You should imagine that each needle you enter is entered as is but will be transfor from needle to *needle*
        e.g. if you want to search for a.exe and provide needle a.exe
        The script will search for *a.exe* and return any findings
    
    .PARAMETER needles
        Search terms. It can be provided in form of array.
        e.g. if you want to search for a.exe and b.exe you can do something like
        $searchTerms = @("a.exe","b.exe") and then pass it over to this function

    .PARAMETER lines
       This is the output of the Get-Fullpath function

    .INPUTS
        - Needles
        - Lines

    .OUTPUTS
        Findings

    .EXAMPLE
        # Mutliple filenames
        $searchTerms = @("a.exe","b.exe")
        Get-Needles -lines $lines -needles @searchTerms

        # Single filenames
        $searchTerm = "a.exe"
        Get-Needles -lines $lines -needles @searchTerm

    #>
  
param(
    [string[]]$needles,
    [string[]]$lines
)
    $needleresults = $null
    $needleresults = @()
    $needles = $needles -join "|"
    $regex = [regex]::new("(?i)^.*?($needles).*","Compiled")
    [Func[String,bool]] $delegate = { param($d); return $regex.Matches($d)}

    $needleresults += [Linq.Enumerable]::Where($lines,$delegate)
  
    return $needleresults
}

$drives = Get-PhysicalDrives -DrivesExclude $DrivesExclude # Get Drives
$gduPath = Get-GDUPath  # Get GDU executable path
$searchresults = [System.Collections.ArrayList]@() # Create arraylist to store results

Write-Verbose "Searching for the following needles:" 
Write-Verbose "$($needles -join "`r`n")`r`n"
foreach ($drive in $drives)
{
    $global:jsonresults = [System.Collections.ArrayList]@() # Create an arraylist to hold json results
    $txt = $null  # empty variable that holds fullpaths
    $json = $null # empty variable that holds gdu json results 
    $gdustopwatch =  [system.diagnostics.stopwatch]::StartNew() # Create a stopwatch to count how long it takes to scan


    Write-Verbose "Scanning $($drive.DriveLetter):\..." 

    # Run GDU and if GCValue has been passed, pass it to GDU
    if ($GCValue)
    {
        $json = Invoke-GDUPath -gduPath $gduPath -drive $drive.DriveLetter -maxCores $maxCores -GCValue $GCValue
    }else {
        $json = Invoke-GDUPath -gduPath $gduPath -drive $drive.DriveLetter -maxCores $maxCores
    }
    
    $gdustopwatchTime = [math]::Round($gdustopwatch.Elapsed.TotalSeconds,2)
    $gdustopwatch.Stop()
    Write-Verbose "GDU Scanning completed [$gdustopwatchTime secs.]" 
    $txtstopwatch =  [system.diagnostics.stopwatch]::StartNew()
    Write-Verbose "Getting FullPaths" 
    $txt = Get-FullPathInitiator -jsondata $json # Invoke the helper function to get from JSON to FullPaths
    $txtstopwatchTime = [math]::Round($txtstopwatch.Elapsed.TotalSeconds,2)
    $txtstopwatch.Stop()
    Write-Verbose "Fullpaths Completed [$($txt.Count) files][$txtstopwatchTime secs]" 
    $needlestopwatch =  [system.diagnostics.stopwatch]::StartNew()
    Write-Verbose "Checking for Results"
    
    [void]$searchresults.Add((Get-Needles -needles $needles -lines $txt)) # Get the results and dump them in an arraylist
    $needlestopwatchTime = [math]::Round($needlestopwatch.Elapsed.TotalSeconds,2) 
    $needlestopwatch.Stop()
    #Write-Verbose "TxtCount: $($txt.Count)" -ForeGroundColor Red
    Write-Verbose "Results returned [$needlestopwatchTime secs.]" 
    Write-Verbose ""
}
# There is a bug in gdu where the root path of the drive will have to \\, convert them to single.
$searchresults = $searchresults | Foreach-Object{$_.Replace(':\\',':\')} 
Write-Verbose "Results:`r`n"
Write-Host "$($searchresults | fl | Out-String )" -ForeGroundColor Green

if ($OutputFilePath)
{
    $searchresults | Out-File $OutputFilePath -Encoding "UTF8" -Force
}