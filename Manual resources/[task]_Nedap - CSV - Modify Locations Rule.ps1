$locationsNew = $form.dualList.right.toJsonString
$locationsOriginal = $form.locationMappings.NedapLocationIds
$organisationalUnit = $form.locationMappings.AFASOEid

#Step 1 - delete rule
$path = $NedapOnsLocationMappingPath

$CSV = import-csv $Path -Delimiter ";"
$filteredCSV = foreach ($line in $CSV) {
    if (-not(($line.'Department.ExternalId' -eq $organisationalUnit) -and ($line.NedapLocationIds -eq $locationsOriginal))) {
        $line 
    }
}
$filteredCSV | ConvertTo-Csv -NoTypeInformation -Delimiter ";" | % { $_.Replace('"', '') } | Out-File $path

#Step 2 - add new rule definition
$afasLocation = $organisationalUnit
$nedapLocations = $locationsNew | ConvertFrom-Json

foreach ($n in $nedapLocations) {
    $nedapLocationString = $nedapLocationString + $n.Id.ToString() + ","
}

$nedapLocationString = $nedapLocationString.Substring(0, $nedapLocationString.Length - 1)

$rule = [PSCustomObject]@{
    "Department.ExternalId" = $afasLocation
    "NedapLocationIds"      = $nedapLocationString
}

$rule | ConvertTo-Csv -NoTypeInformation -Delimiter ";" | ForEach-Object { $_ -replace '"', "" }  | Select-Object -Skip 1  | Add-Content $Path -Encoding UTF8

$Log = @{
    Action            = "Undefined" # optional. ENUM (undefined = default) 
    System            = "NedapOns" # optional (free format text) 
    Message           = "Updated location rule for department [$organisationalUnit] from  Nedap Location id(s) [$locationsOriginal] to Nedap Location id(s) [$locationsNew] in mapping file [$path]" # required (free format text) 
    IsError           = $false # optional. Elastic reporting purposes only. (default = $false. $true = Executed action returned an error) 
    TargetDisplayName = "$path" # optional (free format text) 
    TargetIdentifier  = "" # optional (free format text) 
}
#send result back  
Write-Information -Tags "Audit" -MessageData $log 
