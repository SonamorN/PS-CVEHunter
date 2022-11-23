# PS-CVEHunter
A boilerplate of script that searches for given filenames in given or all disks on your system that belong to CVEs. Under the hood gdu is used to pull dirs and filenames.

# What does this script do?
This script searches for given filenames in the given system drives and returns results

# Why to use this script?
In the last few months/years more and more CVEs are coming up that can be detected by searching
for certain filenames
e.g.
- log4j
- Apache Text commons 
and probably more but these were a few of the ones I had to deal with

# What is gdu and why the script needs it?
Have you ever tried using Get-ChildItem for a whole drive?   

Run it, go grab a beer, then a second beer, come back and it will still be running. 
Now go grab a third beer, keep doing this till it's finished.  

Now you are wasted and you can't do anything with the results. 

gdu provides a fast and easy way to get all the filenames and directories from a given
path within a few seconds. More about it here https://github.com/dundee/gdu

# So is this a finished script, can I use it?
Most certainly, if you want to search for a given string of a filename on your drives, then
yes, you may use it but this script has more of a sense of a boilerplate, to download it
and change it in a way that benefits you.

# So how fast is this?
This was a search for MigRegDB.exe.mui in C Drive which holds 886946 files.  
The script ran with 16 cores, on a AMD Ryzen 3700X, on an NVME disk
It took roughly 125 seconds to provide results
```
VERBOSE: Searching for the following needles:  
VERBOSE: MigRegDB.exe.mui  
VERBOSE: Scanning C:\...  
VERBOSE: GDU Scanning completed [19.54 secs.]  
VERBOSE: Getting FullPaths  
VERBOSE: Fullpaths Completed [886946 files][39.03 secs]  
VERBOSE: Checking for Results  
VERBOSE: Results returned [66.4 secs.]  
```

# OK I am sold how to use this?
* Step 1.
Download the script
Place in a folder of your choice
* Step 2.
Download windows gdu version from:
https://github.com/dundee/gdu
* Step 3.
Check the script's documentation on how to run it.

# OK how to run this?
The script is kinda well documented and I will show some examples here.
As this is intended to be a boilerplate rather than a script to copy, paste and run, I won't give too much info. 

Search for a.exe, with 16cores, provide more info, output the results to a txt file and exclude disk C

```
.\PS-CVEHunter.ps1 -needles "a.exe" -maxCores 16 -Verbose -OutputFilePath "C:\1.txt" -DrivesExclude "C"
```
Search for both a.exe and b.log, with default number of cores (max 8), without garbace gollector, on all disks
```
.\PS-CVEHunter.ps1 -needles "a.exe,b.log"
```

# What are needles and why needles?
If your drives are the haystack the needles are your search terms.

# How is the script searching for a needle(s) 
It uses the following regex
`(?i)^.*?($needle).*`
The search function is using a combination of a compiled regex and LINQ
to scan through a list of filepaths extremely fast. Scanning ~900000 entries
in ~66 seconds.

# Explain this regex to me...
I am too lazy, see regex101 explanation, where needle are your search terms:
```
(?i) match the remainder of the pattern with the following effective flags: i
i modifier: insensitive. Case insensitive match (ignores case of [a-zA-Z])
^ asserts position at start of the string
. matches any character (except for line terminators)
*? matches the previous token between zero and unlimited times, as few times as possible, expanding as needed (lazy)
1st Capturing Group (needle)
needle matches the characters needle literally (case insensitive)
. matches any character (except for line terminators)
* matches the previous token between zero and unlimited times, as many times as possible, giving back as needed (greedy)   
```

# Why do you call this a CVE Hunter? it's a mere filename searcher
Because CVE detection is why I use the script, if I want to search for a specific file I either use file explorer, everything from void tools or something in between.    
This script is to be used in server environments to return filenames that are related to CVEs.

It is in the same sense that you don't call every vehicle a car. Some of them might be trucks doing a certain job better. 

