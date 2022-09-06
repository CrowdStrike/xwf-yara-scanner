#  Overview

This [X-Ways Forensics](http://www.x-ways.net/forensics/) [X-Tension](http://www.x-ways.net/forensics/x-tensions/) allows the use of [YARA](https://github.com/VirusTotal/yara) within X-Ways natively. It uses both the [X-Ways Forensics API](http://www.x-ways.net/forensics/x-tensions/api.html) and the [YARA API](https://yara.readthedocs.io/en/stable/capi.html) to achieve this.

_Note: This is an open source project, not a formal CrowdStrike product._

There are many benefits to running YARA within X-Ways, versus running YARA via the command-line interface.
* No need to mount the target media, the X-Tension will read each file within the case snapshot into memory and be scanned there. No files are written to disk.
* Allows the user to use the powerful filters within X-Ways to limit the scope of the YARA scan.
* Because the X-Tension uses the power of X-Ways, YARA will scan all files within the current snapshot. This includes carved files, decompressed archives, files within archives within archives etc. 
* Any confirmed YARA hits will be saved back to X-Ways via the comments and Report Table columns, vs stdout (which can get unruly quickly if scanning a mounted drive). 

#  Requirements

* A license for X-Ways Forensics (version v19.9 SR-7 and later)
* A set of YARA rules

#  How to Install
Assuming that X-Ways Forensics is installed and setup correctly, simply download the compiled DLL from the [releases page](https://github.com/CrowdStrike/xwf-yara-scanner/releases) and copy it into your *x64* folder within the X-Ways Forensics install folder.

#  How to Use
The X-Tension can be executed via the X-Ways Forensics GUI or via the X-Ways Forensics command-line. This readme will focus on the GUI method.

Within the GUI, there are two ways to execute the X-Tension; via the Refine Volume Snapshot ("RVS") menu, or via the Directory Browser Context ("DBC") menu. Which method depends on what you are trying to achieve. Typically, running YARA via the RVS menu will be very fast if the user specifies a sensible maximum file size (for example 25MB). If for any reason the user wants to run YARA against larger individual files via the DBC menu, the X-Tension will split the data up into chunks (the size of which is provided by the user).

**If any of the YARA rules fail to compile**, an error will be displayed within the X-Ways Messages window showing which line the error occurred on, and the YARA error message. Fix these errors within the YARA rule and try again. A count of YARA warnings will be displayed via the X-Ways Messages window, and the exact details of these warnings are logged in the X-Ways case log. 

The X-Tension supports the usage of multiple YARA rule files (note that YARA will throw an error for duplicate rules and fail to compile). Alternatively it also supports the usage of a singular already compiled rule file (.yara/.yar).

_Note: There is a risk that a valid YARA hit is missed if the scanned data resides across two chunk/buffer boundaries. If this is a problem, increase the buffer size or copy the file out of X-Ways and scan using the YARA command-line interface._

| Method -> | RVS | DBC |
|--|--|--|
| Multi-threaded | Yes | No |
| Prompt for maximum file size | Yes | No |
| Prompt for scan buffer size | Yes* | Yes |

\* Only if the maximum file size entered by the user is larger than 100MB. If the maximum file size is smaller than 100MB, it uses 100MB as the buffer size.

###  Refine Volume Snapshot
Within the GUI, once you have created or opened a previously existing case, go to Specialist -> Refine Volume Snapshot. Then check the option "Run X-Tensions" and click the three dots that appear. Within the menu that pops up, click on the plus (+) symbol and navigate to the **XT_Yara.dll** file downloaded from this repository, then press OK. 

You will then be prompted to select your YARA rule file. An input window will be displayed and you will then be asked to provide a maximum file size to scan, which is required. 25-50MB could be an adequate maximum size if you are only looking for malware samples or web shells for example.

If the user has selected a maximum file size of more than 100MB, a second user input prompt will be displayed asking for the buffer size used by the YARA scanner. It has been tested up to 2GB with no problems, but select wisely depending your memory constraints and number of selected threads.

###  Directory Browser Context Menu
Within the GUI, once you have created or opened a previously existing case, select the file(s) you wish to scan and then right click one of them and select "Run X-Tensions...". You will then be prompted to specify the YARA rules file(s). A user input prompt will be displayed asking for the buffer size used by the YARA scanner. It has been tested up to 2GB with no problems, but select wisely depending your memory constraints and number of selected threads. 

There is no prompt for maximum file size.

#  How to Read the Output
Files with YARA hits are added to the Report Table called "YARA Hits". The exact rules that hit are added per file, per line, within the "Comments" field inside X-Ways Forensics. 

Typical output is shown below:
```
[XT] YARA 4.2.2 library initialised
[XT] There were 9 YARA compile warnings. Check the XWF case log for details
[XT] YARA rules compiled successfully
[XT] Operation Complete. Processing time: 0.000000s
[XT] Summary: Found 240 YARA hits
[XT] YARA library finalised
```

#  Troubleshooting
* You see the error message "Stubborn X-Tension DLL. Force unload?". This happens when the DLL remains loaded even after X-Ways calls FreeLibrary(). After clicking Yes, X-Ways Forensics tries calling FreeLibrary() a second time, which should succeed. 
