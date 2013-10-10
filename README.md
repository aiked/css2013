# CSS 2013 #

[Homepage] (http://www.iwsec.org/css/2013/english/index.html)

## Intro ##

In this repo we will collect the tools needed bla bla bla...
>Note: We only have less than a month to get ourselves ready!

## Current Progress so far ##

 - [x] Collect some tools and install them.
 - [x] Gather a couple of useful documents.
 - [ ] Check older CTFs and stuff, to get an idea of what this will all about.
 - [ ] Track our progress.

## Useful links ##

In this section we will put links of various documents and tools. 

### Tools ###
  
#### Network Forensics/Analysis ####

  * Wireshark
  * tcpdump
  * ettercap

#### Malware Analysis ####

  * Cuckoo Sandbox
  * objdump
  * IDA
  * libemu
  * JD-GUI
  * dex2jar
  * flasm
  * swftools
  * Yara
  * Custom scripts... (MDScan)
  * [OfficeMalScanner](http://www.aldeid.com/wiki/OfficeMalScanner) (for Office documents. Run it under wine)

#### Stats Visualizer ####

  * AWStats (useful for apache logs)

#### Mobile Forensics ####

  * Androguard
  * DroidBox
  * baksmali/smali
  * apktool
  * TaintDroid
  * DroidScope

#### Penetration testing/Information gathering ####

  * Metasploit
  * NMap

### Documents ###

  * [ENISA Exercises Handbook] (http://www.enisa.europa.eu/activities/cert/support/exercise/files/handbook). Check below for VMs.
    You can read Exercises 7 (/Network Forensics/), 9 (/Large Scale Incident Handling/).
  * An interesting [category on Wikibooks] (https://en.wikibooks.org/wiki/Category:Software_reverse_engineering) concerniing Reverse
    Engineering.
  * A list of [IDA tutorials] (https://www.hex-rays.com/products/ida/support/tutorials/) provided by Hex-Rays.
  * Another [tutorial](securityxploded.com/reversing-basics-ida-pro.php) for Reverse Engineering with IDA
  * [RE for Beginners] (http://yurichev.com/writings/RE_for_beginners-en.pdf). 
  * Kris Kendall's [Practical Malware Analysis](http://www.blackhat.com/presentations/bh-dc-07/Kendall_McMillan/Paper/bh-dc-07-Kendall_McMillan-WP.pdf)
  * A [list] (http://computer-forensics.sans.org/blog/2011/06/09/android-mobile-malware-analysis-article) of articles for Android malware analysis
  * Beginner's guide to [Smali coding](http://forum.xda-developers.com/showthread.php?t=2193735)
  * Reference guide to [Davlik opcodes](http://pallergabor.uw.hu/androidblog/dalvik_opcodes.html) and examples how typical [code structures](http://androidcracking.blogspot.gr/2011/01/example-structuressmali.html) are represented in Smali code. (**MUST** for Android RE)
  * [Guide](http://blog.apkudo.com/2012/10/16/reverse-engineering-android-disassembling-hello-world/) for dissasembling a Hello World application in Smali

### Others ###

Let's insert here other useful stuff. Useful links from older CTFs etc

 * [iCTF] (http://ictf.cs.ucsb.edu/) from UCSB
 * A [GitHub wiki] (https://github.com/isislab/Project-Ideas/wiki/Capture-The-Flag-Competitions) worth visting.
   Contains a loadful of information about Capture the Flag competitions. (**Must read** (?))
 * [CERT Exercises] (http://www.enisa.europa.eu/activities/cert/support/exercise/images-for-CERT-exercises) from ENISA.
   Exercise material, tools and hanbook are bundled in a VM. Donwload it and give it a try.
 * Some YouTube videos about traffic analysis ([1](https://www.youtube.com/watch?v=U0QABcTD-xc), [2](https://www.youtube.com/watch?v=UXAHvwouk6Q))

 * [HOIC vs LOIC] (http://blog.spiderlabs.com/2012/01/hoic-ddos-analysis-and-detection.html)
 * [test your skills via puzzles!] (http://forensicscontest.com/2009/10/10/puzzle-2-ann-skips-bail)
 * [Shellcode analysis](http://www.malwaretracker.com/shellcode.php) tool from malwaretracker.com
 * [Malware Cookbook](https://code.google.com/p/malwarecookbook).
 * A site offering [pacp files](http://www.netresec.com/?page=PcapFiles) to public.

Reverse Engineering 

>Notice: most tools i can find are meant for windows...

 * [jd-gui] (http://code.google.com/p/denzfarid/downloads/detail?name=jd-gui-0.3.3.linux.i686.tar.gz&can=2&q=) 
	java decompiler you should sudo apt-get install ia32-libs-gtk

 * [dex2jar] (http://code.google.com/p/dex2jar/downloads/detail?name=dex2jar-0.0.9.15.zip&can=2&q=) 
	converts dex or apk files to jar (for android apps)

 * [flasm] (http://www.nowrap.de/flasm.html) swf decompiler 

 * [swftools] (http://www.swftools.org/about.html) swf decompiler
