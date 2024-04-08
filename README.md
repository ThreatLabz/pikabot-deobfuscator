# Pikabot Deobfuscator
An IDA plugin to deobfuscate Pikabot's strings using RC4 and AES

# Compatibility
The Pikabot plugin has been tested with IDA versions 8 and newer. The plugin can be executed by compiling the source code using IDA's SDK and/or copying the generated DLL into the IDA plugins folder. After a Pikabot sample is loaded, the user can decompile a function and right-click in the decompiled output and either choose to decrypt strings in the current function or in all of them.

![](https://www.zscaler.com/cdn-cgi/image/format=auto/sites/default/files/images/blogs/fig_3_3.png)

For each decrypted string, the plugin sets a comment in the decompiled output.

# Before
![](https://www.zscaler.com/cdn-cgi/image/format=auto/sites/default/files/images/blogs/fig_4_2.png)


# After

![](https://www.zscaler.com/cdn-cgi/image/format=auto/sites/default/files/images/blogs/fig_5_1.png)


# Example Pikabot Samples
|SHA256|
|:------------------------------------------------------------------|
|aebff5134e07a1586b911271a49702c8623b8ac8da2c135d4d3b0145a826f507|
|4c53383c1088c069573f918c0f99fe30fa2dc9e28e800d33c4d212a5e4d36839|
|15e4de42f49ea4041e4063b991ddfc6523184310f03e645c17710b370ee75347|
|e97fd71f076a7724e665873752c68d7a12b1b0c796bc7b9d9924ec3d49561272|
|a9f0c978cc851959773b90d90921527dbf48977b9354b8baf024d16fc72eae01|
|1c125a10c33d862e6179b6827131e1aac587d23f1b7be0dbcb32571d70e34de4|
|62f2adbc73cbdde282ae3749aa63c2bc9c5ded8888f23160801db2db851cde8f|
|b178620d56a927672654ce2df9ec82522a2eeb81dd3cde7e1003123e794b7116|
|72f1a5476a845ea02344c9b7edecfe399f64b52409229edaf856fcb9535e3242|

