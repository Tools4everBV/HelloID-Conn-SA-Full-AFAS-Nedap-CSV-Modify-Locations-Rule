#Step 1 - delete rule
$Path = $NedapOnsLocationMappingPath

$CSV = import-csv $Path -Delimiter ";"
$filteredCSV = foreach ($line in $CSV) {
    if (-not(($line.'Department.ExternalId' -eq $organisationalUnit) -and ($line.NedapLocationIds -eq $locationsOriginal))) {
        $line 
    }
}
$filteredCSV | ConvertTo-Csv -NoTypeInformation -Delimiter ";" | % { $_.Replace('"', '') } | Out-File $Path

#Step 2 - add new rule definition
$afasLocation = $organisationalUnit
$nedapLocations = $locationsNew | ConvertFrom-Json

foreach ($n in $nedapLocations) {
    $nedapLocationString = $nedapLocationString + $n.Id.ToString() + ","
}

$nedapLocationString = $nedapLocationString.Substring(0, $nedapLocationString.Length - 1)

$rule = [PSCustomObject]@{
    "Department.ExternalId" = $afasLocation;
    "NedapLocationIds"      = $nedapLocationString;
}

$rule | ConvertTo-Csv -NoTypeInformation -Delimiter ";" | ForEach-Object { $_ -replace '"', "" }  | Select-Object -Skip 1  | Add-Content $Path -Encoding UTF8