# UMDCTF

This includes my write-up for UMDCTF which had many interesting and new forensics challenges along with other categories!

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787061/xwwdi0uadrtb2t6lbvoe.png)

We finished 37th, top 6.6%!

### Forensics

### 1. Renzik’s Case (usb.img)

We’re given an image file `usb.img` which after loading in FTK shows the deleted files from the unallocated space. Simple one to begin with, nothing too complex.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787062/ghlbjlsbzjfxohxwhhth.png)

**UMDCTF{Sn00p1N9\_L1K3\_4\_SL317H!}**

### 2. How to Breakdance (.pcap USB data)

For this one, we are given a `.pcap` file, which seems to include USB data.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787063/rxd6resprbw3etu4woeu.png)

Quickly going through the packets, you can notice the section of data that changes and one that stays the same. The interesting field here is `Leftover Capture Data` which includes the keystroke data sent from the keyboard to the host. Also notice that all packets have a field `usb.urb_type` which determines the direction of data transmission. `URB_COMPLETE` & `URB_SUBMIT` are the possible values for the same. We are looking for the direction keyboard to host, so let’s apply a filter for it: `usb.urb_type==URB_COMPLETE`

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787064/ev8nzi19as4gvdrluox7.png)

The 8th byte will be set to a ‘C’ or an ‘S’ depending on the direction and the last 5 bytes (Byte 64–68) is what we want to extract which is the leftover capture data.

To get all the leftover capture data we can use tshark to redirect the output. We apply the same filter to get all the packets from keyboard to host first and then export the `usb.capdata` field which is our ‘Leftover Capture Data’ in wireshark.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787065/daoqok5jrbunni5aoqsy.png)

`tshark -r how_to_breakdance.pcapng -Y ‘usb.urb_type==URB_COMPLETE’ -T fields -e usb.capdata > keystrokes.txt`

Now all we need to do is map the HID usage codes in hex to the actual keys pressed. I wrote a python script to do the mapping and then removed all the newlines to get a big chunk of text to work with.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787066/ujl68e44bwrvlwthxrvu.png)

**UMDCTF{1\_luv\_70\_f1nd\_c7f\_fl46s}**

### 3. Magic Plagueis the Wise (zip corruped .png)

For this one, we’re given a large `.zip` file which had numerous `.png` files. Opening up the first image in HxD we can see a byte worth of data replacing the first byte of the default file signature for a `.png` which should be a `%` in ascii. Fixing the header results into a blank image for all files, which means the data that is being written is of interest.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787067/dbgvme7hzvbcdrhfkykm.png)

This pattern follows throughout the entirety of 4464 images.

We can extract the first byte from all files like so: `head -c 1 * > firstchars.txt`and then simply process out the data from the additional noise.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787068/g6v0s1o5rhcfhwoinbfb.png)

**UMDCTF{d4r7h\_pl46u315\_w45\_m461c}**

### 4. jdata (img with binary inside it)

For this we have a `.zip` file that includes only an image inside at first glance, but I found a binary embedded inside it.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787069/nsd8pbaahdaxyrl9sfq4.png)

Extract the elf binary so we can take a look in ghidra.

`binwalk — dd=’.*’ jdata.zip` will search and extract every known file signature embedded.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787070/gcc5naonwbopgq6kglfg.png)

There is a function called **hehe**, which calls many other functions which only have a return statement. The function identifiers however, spell out something in reverse.

`ghidraisforbinariesbroand` is the first half of the flag.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787071/ycyqtsnthprqowhntehk.png)

Second half is in plaintext in the image, as aptly shown by the much useful red ellipse and arrow :) **UMDCTF{ghidraisforbinariesbroandpubl1sh\_s0m3\_r3al\_w0rk}**

### 5. Class Project (VM image)

For this we’re given a VM image. In time crunch, instead of booting it up as a VM with provided password, I mounted it with Arsenal and used FTK to quickly look for interesting files in the filesystem.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787072/xoq9md2zc7r8nrqk7eah.png)

Right away, we have the flag base64 encoded.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787073/usimyvfykpmycgakzwxd.png)

**UMDCTF{f0rk\_b0mb5\_4r3\_4\_b4d\_71m3}**

### 6. Kernel Infernal 1 (Kernel dump)

This was the first time I came across a `.kdump` file. It stands for Kernel Dump, which is a mechanism in the Linux kernel to capture memory during a Kernel Panic. I used the crash utility to debug the memory dump.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787074/ngypfwqatrdk2xxkwpbl.png)

From the prompt we can see it hinting at **pwd**.

The crash utility accepts 2 parameters, first is the Linux Kernel Object File that has the debugging switch set. You can get it from the corresponding OS index. Here we have a dump from `ubuntu20.04–5.4.0–99-generic` so find the equivalent debug symbol package and grab the object file from it.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787075/ylgeozcpbxx9zjogvefc.png)

The hint was ‘**pwd**’ which stands for present working directory, so I examined the backtrace first to determine which process caused the kernel panic. Then we can use the file command with the PID of that process.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787076/j1dy7dfya3a6ydoef6zl.png)

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787078/lvp6nn3mv8yls1yfsefg.png)

We can see a bash process with PID 5206 in backtrace.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787079/jfztxwcf2ilpwk4unckt.png)

Here we can see the current working directory for the same process.

The challenge author wasn’t aware of the `files` command, and posted the intended solve on discord, which I wasn’t able to replicate but basically you have to traverse the `task_struct` structure to get the directory name, similar to how we would traverse an `_EPROCESS` structure to get ‘next process name’ and ‘previous process name’ from `ActiveProcessLinks` structure in a Windows memory dump.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787079/ybalhticv4m3e3hrbxcp.png)

**UMDCTF{T0ta11yCR45H!!}**

### 7. Still Crusin’ (VM password protected)

Again we have a VM image zipped and password protected, and an encrypted pdf. I started by cracking the pdf password using `john`.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787080/kvhjyzwxfevsqvcr7fkj.png)

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787081/enqwa1ulrvd0atgdmqem.png)

Use the same password to extract the VM image.

Again, I just wanted to look at the filesystem so I didn’t boot up as it would take a lot of time. This time instead of FTK, I used R-studio as FTK wasn’t showing me some necessary deleted files. There were many deleted audio and image files to misdirect the players into deep steganography and spectral analysis rabbit holes. However I was able to find this hint so I quickly pivoted.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787082/nfrnwsswiupkth9bewip.png)

I found this hint in this deleted file, to which my first thought was to do a keyword search.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787084/udyubbhyegvhznhzuvfw.png)

**UMDCTF{7h3r3'5\_4\_pl4c3\_c4ll3d\_k0k0m0}**

### 8. Kernel Infernal 2 (Kernel Dump)

For this one, we’re asked to find the address of the CR3 register.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787085/uonkof83brpbkrxiohx7.png)

CR3 enables the processor to translate logical addresses into physical addresses by locating the page directory and page tables for the current task.

CR3 contains the physical address of the page of the page directory table, so it is also called PDBR. This value is unique for each running process, since every process has it’s own page table.

So, we just need to walk the `task_struct` to get to the `pgd` pointer.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787086/hhvo7zoyrcoqtcxxbutp.png)

**UMDCTF{0xffff9b187a8e6000}**

### Misc

### 1. ChungusBot v2

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787087/m0i3f5l9tul4ibeb2vex.png)

Visiting UMDCSEC’s github, we can find it’s [repo](https://github.com/UMD-CSEC/ChungusBot\_v2/blob/main/chungus.py).

We had to use this Discord bot and it’s custom commands to make it reveal the flag. After looking at the code I noticed there were two checks, one checking the amount of pixels same as the bot’s Discord profile picture, and other is some value in 45–50 & 14–19. I tried fetching the original source of the profile picture using Discord web app, but I just couldn’t reach the demanding 92% similarity.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787088/jmgrr0hre97skwwc0wyj.png)

There is a command missing from here called ‘tellme avatar’.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787089/vw4ryd1njlmaf43yvbum.png)

The function check1 verifies the pixel similarity. (See code)

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787089/fctrfhdmxmdccltrccw2.png)

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787091/amzdojwsvu7ehfmm5xxk.png)

It gives us an image to work with. Now we just have to remove the red lines enough to match at 92% similarity.

I used the good old MS Paint to set the exact black used for background, remove majority of the reds, and set it as my Discord profile picture. That second check was for the metadata of the image created and not when you use the command. So while the minutes fall in that custom range, save the edited picture.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787092/xtogcde1hsyquzacnnjd.png)

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787093/l4rwxv5aez9dlwtkqbun.png)

`**UMDCTF{Chungus_15_wh0_w3_str1v3_t0_b3c0m3}**`

### 2. RSI 2

We’re provided with `.osr` files which are replay files for the game ‘osu!’. So, naturally I install the game and try to open the file in it.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787094/yx5ox4n8bpo0jdwsftno.png)

I’m faced with this error.

After looking around, I found the API for this game which can be used to find out the `beatmap_id` value and download it so we can see the replay file.

First we need to generate an API key, we can do that [here](https://osu.ppy.sh/p/api/). Register yourself and generate a key to use.

Reading the official API [docs](https://github.com/ppy/osu-api/wiki#apiget\_beatmaps), `get_beatmaps` needs `k` and `h` for our scenario.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787095/aehmtgyur1dqtfj1skqk.png)

To get the beatmap hash, we can again refer to the `.osr` file structure and obtain it.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787096/zquo3hjb2eyycficjqtw.png)

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787097/a8rvmbuk7fdnwjlkqp9g.png)

We can now send the following request:

`https://osu.ppy.sh/api/get_beatmaps?k=<YOUR_API_KEY_HERE>&h=2d687e5ee79f3862ad0c60651471cdcc`

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787098/rdstzpq7bzsjmotayqzl.png)

Now we have the **beatmap\_id.**

We can go to following URL to download and install the beatmap:

`[https://osu.ppy.sh/s/131891](https://osu.ppy.sh/s/131891)`

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787099/ougoagmbatoumtgup6yz.png)

Now, we can view our replay which reveals the flag but it isn’t very clear. So I switched to a different approach. I studied the `.osr` file structure which is officially documented [here](https://osu.ppy.sh/wiki/en/Client/File\_formats/Osr\_\(file\_format\)). The Replay data is LZMA compressed. So, I decompressed the data and we have values in the format mentioned in the file structure.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787100/olmdg9r47dgmgte2v6rn.png)

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787101/humbtiyftnpejqlottbx.png)

We can safely discard **w** and **z** values.

Now that we have our coordinates, we can plot them and find the flag in clear text!

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787103/z4qbp3i7dgdgnuyo2aca.png)

The flag is flipped vertically, after moving around we can see it: **UMDCTF{CL1CK\_TO\_THE\_BEAT}**

### 3. RSI 1

For this one, we are only concerned with this Byte Array.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787104/stwerqjxy1rixhyggljr.png)

This compressed data is what we’re after.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787105/d8t81d9aks1frpe1lprs.png)

Map out the section using the file structure. The LZMA compressed data is highlighted here.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787106/xloj5in5bvmrs5cbhsve.png)

Decompressing the LZMA stream gives us ascii values which we can decode.

![.gitbook/assets/1663787062.png](http://res.cloudinary.com/dr4gsg09f/image/upload/v1663787108/hzijjqm6wguctknvn6n0.png)

**UMDCTF{wE1c0m3\_t0\_o5u!}**
