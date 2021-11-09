# volatility3_plugin

Following an article I found very interesting : https://volatility-labs.blogspot.com/2021/10/memory-forensics-r-illustrated.html

In that article, it was explained how a new plugin was written to check if a mimikatz Skeleton key was applied while checking the memory.

I wrote a CTF write-up a while ago on a challenge where you had to find the skeleton key.

Here is the write-up article : https://github.com/k4nfr3/CTF-writeup/blob/master/2019-Insomnihack/Readme.md#skeleton-in-the-closet

I wanted to experiment writing my first volatility3 plugin and it had to be fun, interesting but not too complicated.

I did not reverse the structure where to find the exact hash, I only analysed what I saw as pre-pend hex data, and it seems to work.


So first, I applied the misc::skeleton on my Lab DC.
I dumped the full memory with WinPMem and transfered it.

I tested the skeleton_key_check plugin, and it worked like a charm !

**python vol.py -f physmem.raw windows.skeleton_key_check.Skeleton_Key_Check**

and then I wrote my new plugin based on a yara rule

**python vol.py -f physmem.raw windows.skeleton_key_get_hash.SkeletonKeyGetHash**

Here is the result :
![Test1](/skeleton1.jpg)


I did the same for the Memory dump of the CTF, and it worked well too.
![Test2](/skeleton2.jpg)


## How to install

Make sure you have the yarascan option enabled in your volatility.
( pip install yara-python )

copy file **skeleteon_key_get_hash.py** to folder **../volatility3/framework/plugins/windows**

copy file **skeleteon.yara** to the same folder **../volatility3/framework/plugins/windows**

## Options

If you place the plugins in a different path, please link the *skeleton.yara **

--yara-file /path/to/skeleton.yara

## BruteForce NTLM Hash

john --format=nt

hashcat -m 1000
