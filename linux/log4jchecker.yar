rule NoLookups_found
{
    meta:
	author = "Sber"
	version = "0.1"
	description = "Process memory signatures for Log4j"
	license = "Just do whatever you want"

    strings:
	$s_env1 = "Dlog4j2.formatMsgNoLookups=true" ascii nocase

    condition:
	$s_env1
}


rule log4j_path_in_memory_found
{
    meta:
	author = "Sber"
	version = "0.1"
	description = "Process memory signatures for Log4j"
	license = "Just do whatever you want"

    strings:
	$a_1 = /.:\\((\w|-|!|\.|\s)+\\)*log4j-core-(1|2)\.(.|..)\.(.|..)\.jar/ ascii nocase
	$a_2 = /file:\/((\w|-|!|\.|\s)+\/)*log4j-core-(1|2)\.(.|..)\.(.|..)\.jar/ ascii nocase
	$a_3 = /.:\/((\w|-|!|\.|\s)+\/)*log4j-core-(1|2)\.(.|..)\.(.|..)\.jar/ ascii nocase

    condition:
	1 of ($a_*)
}