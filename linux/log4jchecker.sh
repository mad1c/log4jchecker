#!/bin/sh
#
#Searching vulnurable jar packages for CVE log4j
#Version 1.0
#Sber/SCST

MemScanYara()
{
local Vulnarable=0
    ps -eo pid,comm | grep -i java | grep -Eo '[0-9].*' | cut -d ' ' -f 1 | xargs -I '{}' yara -s log4jchecker.yar '{}' > yara_results.txt
    while read -r arg1 arg2
	do
	if [ "$lastarg1" = "log4j_path_in_memory_found" ]; then 
	    local lastarg1=""
	if [ "$nolookupsPID" -eq "$lastarg2" ];then
		 nolookups="found"
	else 
		 nolookups="not found"
	fi
	    local cutarg2=`echo $arg2 | cut -b 6- | grep -Eo '(\w|-|\/|\.|\s)*\.jar'`
		if [ "$cutarg2" ];then
		
		echo Java process with PID $lastarg2 use log4j library. Option Dlog4j2.formatMsgNoLookups=true $nolookups in process memory. Library path $arg2
				echo Checking: $arg2
	    local nolookups=""
		Log4jScanFile $cutarg2
		result=$?
		if [ $result -eq 1 ];then
			Vulnarable=1
			fi
	fi
	fi
	if [ "$arg1" = "NoLookups_found" ]; then 
		local nolookupsPID=$arg2
	fi

	if [ "$arg1" = "log4j_path_in_memory_found" ]; then 
	    local lastarg1=$arg1
	    local lastarg2=$arg2
	    Vulnarable=1
	fi
	done < "yara_results.txt" 
[ -e yara_results.txt ] && rm yara_results.txt
return $Vulnarable
}
Log4jCheckDir()
{
local Vulnarable=0
local dst=$1
local cve=$2
local jarafileshash=`find "$dst" -type f -iname "*.class" -or -iname "*.jar" -or -iname "*.war"`
    for fnhash in $jarafileshash
        do
	local res=`sha256sum "$fnhash" | cut -c1-64`
	local VulnFound=`grep -i "$res" log4jhashes.txt | cut -d ' ' -f2`
	if [ "$VulnFound" ]; then
		echo $fname $cve $VulnFound
		Vulnarable=1
		fi
	done 
return $Vulnarable
}

Log4jScanJarLib()
{
#local IFS='\n\r'
local src=$1
local Vulnarable=0
local res=`sha256sum "$src" | cut -c1-64`
local VulnFound=`grep "$res" log4jhashes.txt | cut -d ' ' -f2`
if [ "$VulnFound" ]; then
	echo "$src" "$VulnFound"
	Vulnarable=1
	fi 
Log4jGetVersion $src
local result=$?
if [ $result -ne 0 ];then
	local dst=$(dirname $0)/temp_log4j/$(basename $src)_unpack
	local verstr=$(grep "$version" log4jversions.txt | cut -d ',' -f 1-3)
	for str in $verstr
		do	
		local clsfind=$(echo $str | cut -d ',' -f2)
		if [ "$clsfind" != "none" ];then
		Log4jUnpackZip $src $dst "*"$clsfind
		local result=$?
		if [ $result -eq 0 ];then
			
			local cvefind=$(echo $str | cut -d ',' -f3)
			Log4jCheckDir $dst $cvefind
			local result=$?
			if [ $result -eq 1 ];then
				Vulnarable=1
				fi
			fi
			fi
		done
	fi
return $Vulnarable
}

Log4jScanFile()
{
local fname=$1
local Vulnarable=0
local dst=$(dirname $0)/temp_log4j
[ -e "$dst" ] && rm -rf "$dst"
Log4jGetVersion $fname
local result=$?
if [ $result = 1 ];then
	Log4jScanJarLib $fname
	local result=$?
	if [ $result -eq 1 ];then
		Vulnarable=1
		fi
	else
		local mask=$(cat log4jversions.txt | cut -d ',' -f 4 | awk -v RS='[[:space:]]+' '!a[$0]++{printf "%s%s", $0, RT}')
		for maskstr in $mask
		do
		Log4jUnpackZip $fname $dst $maskstr
		local result=$?
		
		if [ $result -eq 0 ];then
		
		local jarafiles=$(find "$dst" -type f -iname $maskstr)
		if [ $jarafiles ];then
		
		for jar in $jarafiles
			do
			Log4jScanJarLib $jar
			local result=$?
			if [ $result -eq 1 ];then
				Vulnarable=1
				fi
			
			done
		fi
		fi
		done
		
	fi
[ -e "$dst" ] && rm -rf "$dst"
return $Vulnarable
}


Log4jGetVersion() 
{
local src=$1
local dst=`dirname $0`
dst=${dst}/temp_log4j
Log4jUnpackZip $src $dst '*/MANIFEST.MF'
local result=$?
if [ $result -eq 0 ];then
while IFS="," read -r arg1 arg2 arg3 arg4 arg5 arg6
	do
		local title=$(grep "$arg5" $dst/META-INF/MANIFEST.MF)
		if [ "$title" ]; then
			local mask=":"$(echo $(grep "$arg6" $dst/META-INF/MANIFEST.MF) | cut -d ' ' -f2 | tr -d '\r\n')":"
			version=$(echo $arg1 | grep -Eo "$mask")
			if [ $version ]; then
				return 1
			fi
		fi
	done < "log4jversions.txt" 
fi
return 0
}

Log4jUnpackZip()
{
local src=$1
local dst=$2
local mask=$3
unzip -o $src $mask -d $dst > /dev/null 2>/dev/null
return $?
}

if [ -z $1 ]; then
	echo "Must provide correct path or options to start check"
	echo "Use: log4jchecker.sh [-yara] [path]"
	echo "Specify the path to the file or directory to check it"
	echo "Use option -yara to check JAVA apps in running java processes with YARA (Yara must be installed)"
	exit 1
fi

Vulnarable=0
while [ "$#" -ne 0 ]
	do
if [ "$1" = "-yara" ]; then 
	yara=1
	fi
[ -e $1 ] && path=$1
	shift
	done
	
Log4jEnv=$(printenv LOG4J_FORMAT_MSG_NO_LOOKUPS)
    if [ $Log4jEnv ]; then
	echo Environment variable LOG4J_FORMAT_MSG_NO_LOOKUPS set to $Log4jEnv
    fi 

if [ $yara ]; then
	echo Starting check JAVA apps in memory of running java processes with YARA
	command -v yara > /dev/null 2> /dev/null
	if [ $? -eq 0 ]; then 
		MemScanYara
		result=$?
		if [ $result -eq 1 ];then
			Vulnarable=1
			fi
	else
		echo Yara not found, skipping check JAVA apps in memory
		fi
	fi

if [ "$path" ];then
	echo Starting check JAVA apps in $path
	if [ -d "$path" ]; then 
		jarafiles=$(find $path -type f -iname "*.jar" -or -iname "*.war")
		for fn in $jarafiles
			do
			Log4jScanFile $fn
			result=$?
			if [ $result -eq 1 ];then
				Vulnarable=1
				fi
			done    
		else
		Log4jScanFile $path
		result=$?
		if [ $result -eq 1 ];then
			Vulnarable=1
			fi
		fi
	fi
if [ $Vulnarable -eq 0 ];then
	echo Vulnarable packages not found
	fi
return $Vulnarable
