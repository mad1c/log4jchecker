# log4jchecker
Searching vulnurable jar packages for CVE log4j
Searches for vulnerable to known CVE classes in the log4j library on disks and in memory (if Yara is present). Searches not only in separate libraries, but also in cases where the library is assembled into a project. It also partially checks the applied mitigation measures.

Scripts released on Windows and *nix and write for Powershell and sh.
Checker supports searching for log4j libraries versions 1 and 2 with known vulnerabilities:

CVE-2019-17571

CVE-2021-4104

CVE-2021-44228

CVE-2021-45046

CVE-2021-45105
