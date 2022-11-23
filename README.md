# PS-CVEHunter
A boilerplate of script that searches disks for given filenames that belog to CVEs, using gdu.

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
Run it, go grab a beer, then a second one come back and it will still be running
gdu provides a fast and easy way to get all the filenames and directories from a given
path within a few seconds. More about it here https://github.com/dundee/gdu

# So is this a finished script can I use it?
Most certainly if you want to search for a given string of a filename on your drives
yes, you may used it but this script has more of a sense of a boilerplate, to download it
and change it in a way that benefits you.

# So how fast is this?
This was search for MigRegDB.exe.mui in C Drive which holds 886946 files
The script was run with 16 cores on a AMD Ryzen 3700X on an NVME disk
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
Step 1.
Download the script
Place in a folder of your choice
Steps 2. Download windows gdu version from https://github.com/dundee/gdu
Steps 3. Check the scrit's documentation on how to run it.





