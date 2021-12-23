#Searching vulnurable jar packages for CVE log4j
#Version 1.0
#Sber/SCST

function MemScanTask {
$Vulnarable=$false
$jproc=wmic path win32_process get processid,commandline /format:csv
$jproc= $jproc | Select-String -Pattern "java" -SimpleMatch
if ($jproc) {
	foreach ($jstr in $jproc) {
		$jstr_splt=$jstr.line.split(" ")
		foreach ($jstr_opt in $jstr_splt) {
			if ($jstr_opt.Contains(".jar"))	{
				$idx=$jstr_opt.IndexOf(".jar")
				$idx+=4
				$jstr_opt=$jstr_opt.substring(0,$idx)
				if ($jstr_opt[0] -eq '"') {$jstr_opt=$jstr_opt.substring(1)}
				if (Test-Path -Path $jstr_opt) {
					write-host Jar module found in Java process commandline. Checking: $jstr_opt
					if (Log4j-ScanFile $jstr_opt) {$Vulnarable=$true}}
				else {
					write-host Jar module found in Java process commandline. No full path found, check it with full system scan: $jstr_opt
					$memfiles=$memfiles+" "+$jstr_opt
					$memfiles_splt=$memfiles.split(" ")
					$memfiles_splt = $memfiles_splt | select -Unique
					}
				}
			}
		}
	}
return $Vulnarable
}

function MemScanYara {
$Vulnarable=$false
$jproc= tasklist /NH /FO CSV | findstr /I java
if ($jproc) {
	foreach ($jstr in $jproc) {$yres=$yres+(./yara64.exe -s log4jchecker.yar ($jstr.split(",")[1]))}
	foreach ($ystr in $yres) {
		$ystr_splt=$ystr.split(" ")	
		if ($lastarg1 -eq "log4j_path_in_memory_found") {
			$lastarg1=""
			if ($nolookupsPID -eq $lastarg2) {$nolookups="found"} else {$nolookups="not found"}
			$found = $ystr_splt[1] -match '.:(\w|-|\/|\.|\\|\s)*\.jar'
			if ($found) {
				write-host Java process with PID $lastarg2 use log4j library. Option Dlog4j2.formatMsgNoLookups=true $nolookups in process memory. Library path $matches[0]
				write-host Checking: $matches[0]
				if (Log4j-ScanFile $matches[0]) {$Vulnarable=$true}
				}
			}
		if ($ystr_splt[0] -eq "NoLookups_found") {$nolookupsPID=$ystr_splt[1]}
		if ($ystr_splt[0] -eq "log4j_path_in_memory_found") {
			$lastarg1=$ystr_splt[0]
			$lastarg2=$ystr_splt[1]
			}
		}
	}
return $Vulnarable
}

function Log4j-ScanJarLib {
param ($src)
#write-host $src
$Vulnarable=$false
$res=Get-FileHash $src
$VulnFound=Select-String -Path log4jhashes.txt -Pattern $res.hash
if ($VulnFound) {
	$VulnFoundMas=$VulnFound.Line.Split(" ")
	Write-host $fname $VulnFoundMas[1]
	$Vulnarable=$true
	}
$ver=Log4j-GetVersion $src
if ($ver) {
	$ver=":"+$ver+":"
	$ver_str_mas=Select-String -Path log4jversions.txt -Pattern $ver -SimpleMatch
	$fileWithExt = [System.IO.Path]::GetFileName($src)
	$dst=$PSScriptRoot+"\temp_log4j\"+$fileWithExt+"_unpack\"
	[void](New-Item -ItemType Directory -Path $dst -Force)
	foreach ($ver_str in $ver_str_mas){
		$ver_spl=$ver_str.Line.Split(",")
			if ($ver_spl[1] -ne "none") {
			$ver_spl[1]="*"+$ver_spl[1]
			if (Log4j-UnpackZip $src $dst $ver_spl[1]) {if (Log4j-CheckDir $dst $ver_spl[2]) {$Vulnarable=$true}}
			if (Test-Path -Path $dst) {Remove-Item -Path $dst -Include $ver_spl[1] -Recurse}
			}
		}
	}
return $Vulnarable
}

function Log4j-GetVersion {
param ($src)
$dst=$PSScriptRoot+"\temp_log4j\"
[void](New-Item -ItemType Directory -Path $dst -Force)
if (Log4j-UnpackZip $src $dst '*MANIFEST.MF') {
	$title_src=Get-Content -Path log4jversions.txt 
	foreach ($str in $title_src){
		$str_splt=$str.split(",")	
		$title=Select-String -Path $dst"META-INF\MANIFEST.MF" -Pattern $str_splt[4] -SimpleMatch
		if ($title) {
			$version=Select-String -Path $dst"META-INF\MANIFEST.MF" -Pattern $str_splt[5] -SimpleMatch
			if ($version) {
				$versionNum=$version.Line.Split(" ")
				if ($str_splt[0].Contains(":"+$versionNum[1]+":")) {
					if (Test-Path -Path $dst"META-INF\MANIFEST.MF") {Remove-Item -Path $dst"META-INF\MANIFEST.MF" -Recurse}
					return $versionNum[1]
					}
				}

			}
		}
	if (Test-Path -Path $dst"META-INF\MANIFEST.MF") {Remove-Item -Path $dst"META-INF\MANIFEST.MF" -Recurse}
	return $false
	}
if (Test-Path -Path $dst) {Remove-Item -Path $dst -Recurse}
return $false
}

function Log4j-UnpackZip {
param ($src, $dst, $mask)
$zip = [IO.Compression.ZipFile]::OpenRead($src)
$entries=$zip.Entries | where {$_.FullName -like $mask} 
if ($entries) {
	$entries | foreach {
		$dstarc = Split-Path -Path $_.FullName
		[void](New-Item -ItemType Directory -Path $dst$dstarc -Force)
		[IO.Compression.ZipFileExtensions]::ExtractToFile( $_, $dst+$_.FullName)
		}
	$zip.Dispose()
	return $true
	}
$zip.Dispose()
return $false
}

function Log4j-CheckDir {
param ($dst,$cve)
$Vulnarable=$false
$File_names_hash= Get-ChildItem -Recurse  -Path  $dst -Include *.class, *.jar, *.war
foreach ($File_name_hash in $File_names_hash) {
	$res=Get-FileHash $File_name_hash
	$VulnFound=Select-String -Path log4jhashes.txt -Pattern $res.hash
	if ($VulnFound) {
		$VulnFoundMas=$VulnFound.Line.Split(" ")
		Write-host $fname $cve $VulnFoundMas[1]
		$Vulnarable=$true
		}
	}
return $Vulnarable
}

function Log4j-ScanFile {
param ($fname)
if (Test-Path -Path $fname) {
	$Vulnarable=$false
	$dst=$PSScriptRoot+"\temp_log4j\"
	if (Test-Path -Path $dst) {Remove-Item -Path $dst -Recurse}
	[void](new-item $dst -itemtype directory -Force)
	if (Log4j-GetVersion $fname) {if (Log4j-ScanJarLib $fname) {$Vulnarable=$true}}
	else {
		$find_src=Get-Content -Path log4jversions.txt
		foreach ($str in $find_src){
			$str_splt=$str.split(",")
			$mas=$mas+" "+$str_splt[3]
			$mas_splt=$mas.split(" ")
			}
		$mas_splt = $mas_splt | select -Unique
		foreach ($mask in $mas_splt){
			if (Log4j-UnpackZip $fname $dst $mask) {
				$File_names= Get-ChildItem -Recurse  -Path  $dst -Include $mask
				if ($File_names){
					foreach ($File_name in $File_names) {if (Log4j-ScanJarLib $File_name) {$Vulnarable=$true}}
					}
				}
			}
		}
	if (Test-Path -Path $dst) {Remove-Item -Path $dst -Recurse}
	return $Vulnarable
	}
}

$Vulnarable=$false
foreach ($carg in $args) {
	if ($carg -eq "-mem") {$mem=$true}
	if ($carg -eq "-yara") {$yara=$true}
	if ($carg -eq "-alldrive") {$alldrive=$true}
	if ($carg -eq "-full") {$full=$true}
	if (Test-Path -Path $carg) {$inputpath=$carg}
	}
if (!$args[0] -or (!$mem -and !$yara -and !$alldrive -and !$full -and !$inputpath)) {
	Write-host "Must provide correct path or options to start check"
	Write-host "Use: log4jchecker.ps1 [-full] [-yara] [-mem] [-alldrive]|[path]"
	Write-host "Specify the path to the file or directory to check it"
	Write-host "Use option -alldrive to search on all drives in system"
	Write-host "Use option -yara to check JAVA apps in running java processes with YARA"
	Write-host "Use option -mem to check JAVA apps in command line of running java processes"
	Write-host "Use option -full to check with use YARA, command line of running java processes and packages on all drives"

	exit 1
	}

Add-Type -Assembly "System.IO.Compression.Filesystem"
if ($env:LOG4J_FORMAT_MSG_NO_LOOKUPS -eq "true") {write-host Environment variable LOG4J_FORMAT_MSG_NO_LOOKUPS value is true}
if ($full) {
$mem=$true
$yara=$true
$alldrive=$true
$inputpath=$false
}

if ($mem) {
	write-host Starting check JAVA apps in command line of running java processes
	if (MemScanTask) {$Vulnarable=$true}
	}

if ($yara) {
	write-host Starting check JAVA apps in memory of running java processes with YARA
	if (MemScanYara) {$Vulnarable=$true}
	}		

if ($alldrive) {
	write-host Starting check JAVA apps on all disk drives
	$drives = gdr -PSProvider 'FileSystem'
	foreach ($a in $drives) {
		$File_names_scan= Get-ChildItem -ErrorAction SilentlyContinue -Force -Recurse -Path  $a.Root -Include *.jar, *.war
		foreach ($File_name_scan in $File_names_scan) {if (Log4j-ScanFile $File_name_scan) {$Vulnarable=$true}}
		}
	}

if ($inputpath) {
	write-host Starting check JAVA apps in $inputpath
	if (!((Get-Item $inputpath) -is [System.IO.DirectoryInfo])) {if (Log4j-ScanFile $inputpath) {$Vulnarable=$true}}
	else {
		$File_names_scan= Get-ChildItem -ErrorAction SilentlyContinue -Force -Recurse -Path  $inputpath -Include *.jar, *.war
		foreach ($File_name_scan in $File_names_scan) {if (Log4j-ScanFile $File_name_scan) {$Vulnarable=$true}}
		}
	}
if (!$Vulnarable) {write-host Vulnarable packages not found}
exit $Vulnarable