Param(
    [string]$owner,
    [string]$repo
)

Write-Host "Calculating new Production Version:" -ForegroundColor Magenta;

$newVersionStr;

$releasesUrl = "https://api.github.com/repos/$($owner)/$($repo)/releases";

Write-Host "Getting list of releases with '$($releasesUrl)'" -ForegroundColor Blue;
$releasesJSON = Invoke-RestMethod -Uri $releasesUrl -Method Get;

if ($releasesJSON.Count -eq 0) {
    Write-Host "Unable to get releases list with '$($releasesUrl)'" -ForegroundColor Red;
    Write-Host "NOTE: This Script cannot handle the first release" -ForegroundColor Cyan;
    EXIT 1;
}

$latestReleaseJSON = $releasesJSON[0]; 
$latestReleaseVersionStr = $latestReleaseJSON.tag_name;
$isPreRelease = $latestReleaseJSON.prerelease;

if ([string]::IsNullOrEmpty($latestReleaseVersionStr)) {
    Write-Host "Unable read the latest release tag name" -ForegroundColor Red;
    Write-Host "Latest Release Data:" -ForegroundColor Cyan;
    Write-Host -Object $latestReleaseJSON -ForegroundColor Cyan;
    EXIT 1;
}

if ([string]::IsNullOrEmpty($isPreRelease)) {
    Write-Host "Unable read the latest release is pre-release or not" -ForegroundColor Red;
    Write-Host "Latest Release Data:" -ForegroundColor Cyan;
    Write-Host -Object $latestReleaseJSON -ForegroundColor Cyan;
    EXIT 1;
}

$isPreRelease = $isPreRelease -as [bool];
$versionArr = $latestReleaseVersionStr.split(".");

if ($isPreRelease) {
    Write-Host "Preview release is not expected in this repository" -ForegroundColor Red;
    Write-Host "Latest Release Data:" -ForegroundColor Cyan;
    Write-Host -Object $latestReleaseJSON -ForegroundColor Cyan;
    EXIT 1;
}

if ($versionArr[2].Contains("-")) {
        Write-Host "Lastest release '$($latestReleaseVersionStr)' is mentioned as production release but version string has Preview string" -ForegroundColor Red;
        Write-Host "Last Release Data:" -ForegroundColor Cyan;
        Write-Host -Object $lastReleaseJSON -ForegroundColor Cyan;
        EXIT 1;
}

$minorVersion = $versionArr[1] -as [int];
$newMinorVersion = $minorVersion + 1;
$newPatchVersion = 0;

$versionArr[1] = $newMinorVersion;
$versionArr[2] = $newPatchVersion;

$newVersionStr = $versionArr -join ".";

Write-Host "Current version is '$($latestReleaseVersionStr)'" -ForegroundColor Blue;
Write-Host "New calculated version is '$($newVersionStr)'" -ForegroundColor Green;

Write-Host "##vso[task.setvariable variable=NEW_VERSION_STRING]$($newVersionStr)";

Write-Host "Updated new version in global variable" -ForegroundColor Green;