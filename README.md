This branch contains the changes needed to send patches through the server to the WoW Client  
```diff
! NOT RECOMMENDED FOR PRODUCTION
```

Requirements:
- 3.3.5 Client  
- Patched Wow.exe to allow loading of unsigned/badly signed MPQ archives  
- Wow.exe with changed build number and (optionally) version numbers  
- MPQ with Prepatch.lst and related files  
- New entry in auth.build_info table

References:
- [Patch 1](https://pastebin.com/Vdp9wpBT)
- [Patch 2](https://pastebin.com/ESi3em3T)


I would like to thank **schlumpf** and **stoneharry** for their [guide](https://www.dropbox.com/s/fovh9mtrj9tgqd4/Implementing%20in-client%20patching%20for%20World%20of%20Warcraft.pdf?dl=0)
