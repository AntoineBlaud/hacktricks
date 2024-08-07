# Extract Firmware from OT Devices

The Small Outline Integrated Circuit (SOIC) package (Figure 1a) is the most common, especially in small, embedded devices. The standard form is a flat rectangular body, with leads extending from two sides. The leads are formed in a gull wing shape to allow solid footing during assembly to a PCB. This kind of package simplifies the process of firmware dumping, since the pins can be probed easily by grabbing them with a tool, called grabbers (shown later in the blog).

The Very-very-thin Small-Outline No-lead (WSON) package (Figure 1b) is slightly thinner compared to the SOIC design. Instead of having the leads extending from the rectangle, it has some conductive pads. For a vulnerability researcher, this package presents some difficulty in reading the memory content, since we cannot use the grabber. Instead, we have to solder some jumpers or desolder the memory from the PCB.

The last package is the Ball Grid Array (BGA) (Figure 1c). It is a type of surface-mounted packaging used for integrated circuits which can provide more interconnection pins than can be put on a dual in-line or flat package. Unlike the SOIC and the WSON, the BGA package can use the whole bottom surface of the device, instead of just the perimeter.

The pins of this package are the hardest to probe, since they are not accessible from the top of the PCB. Unless they are reachable from the back side of the PBC, the only way to get access to the package pinout is to desolder the memory from the PCB and put it in a socket adapter.

### Types of Flash Memory Packaging

Every electronic component installed on a PCB has a hardware interface that allows the soldering of that component to the PCB. In this blog, we will present the three most common package designs used for PCB mounted memory devices.

![](https://www.nozominetworks.com/wp-content/uploads/2021/09/Hardware-Hacking-BLOG-1a.jpg)

**Figure 1a.** SOIC package.

![](https://www.nozominetworks.com/wp-content/uploads/2021/09/Hardware-Hacking-BLOG-1b.jpg)

**Figure 1b.** WSON package.

![](https://www.nozominetworks.com/wp-content/uploads/2021/09/Hardware-Hacking-BLOG-1c.jpg)

**Figure 1c.** BGA package.

The Small Outline Integrated Circuit (SOIC) package (Figure 1a) is the most common, especially in small, embedded devices. The standard form is a flat rectangular body, with leads extending from two sides. The leads are formed in a gull wing shape to allow solid footing during assembly to a PCB. This kind of package simplifies the process of firmware dumping, since the pins can be probed easily by grabbing them with a tool, called grabbers (shown later in the blog).

The Very-very-thin Small-Outline No-lead (WSON) package (Figure 1b) is slightly thinner compared to the SOIC design. Instead of having the leads extending from the rectangle, it has some conductive pads. For a vulnerability researcher, this package presents some difficulty in reading the memory content, since we cannot use the grabber. Instead, we have to solder some jumpers or desolder the memory from the PCB.

The last package is the Ball Grid Array (BGA) (Figure 1c). It is a type of surface-mounted packaging used for integrated circuits which can provide more interconnection pins than can be put on a dual in-line or flat package. Unlike the SOIC and the WSON, the BGA package can use the whole bottom surface of the device, instead of just the perimeter.

The pins of this package are the hardest to probe, since they are not accessible from the top of the PCB. Unless they are reachable from the back side of the PBC, the only way to get access to the package pinout is to desolder the memory from the PCB and put it in a socket adapter.

### Where is the Firmware? How to Recognize the Flash Memory

Now we know what a flash memory looks like, we can start analyzing the PCB of our target device to find the memory among the hundreds of components on the PCB. Usually, the flash memory containing the firmware communicates with the CPU through Serial Peripheral Interface (SPI). SPI uses an 8-pin interface, so we need to look for a flash memory chip with eight pins.

Figure 2, below, shows the PCB of the Annke N48PBB, which we will analyze and find the flash memory.

The figures above represent the supposed pinout of our flash memory (Figure 9a), with a closer look at it (Figure 9b), to highlight the correct orientation.

![.gitbook/assets/1664530464\_9161.png](https://www.nozominetworks.com/wp-content/uploads/2021/09/idea-icon.png)

_**Pro tip:** One corner of every PCB-mounted component has a small circle. It’s important to orient the circle in the same position for both the schematic and the real component to correctly identify the pinout._

Since this pinout is just a hypothesis, we need to confirm our assumption by measuring the switching activity of each pin. To do that, we can use a logic analyzer.

\[![](https://www.nozominetworks.com/wp-content/uploads/2021/09/Hardware-Hacking-BLOG-10.jpg)

**Figure 10.** Setup and wiring of the logic analyzer.

Now that every pin of the flash memory is connected to the logic analyzer, we can start measuring the voltage values to have an initial idea of the pinout.

\[![](https://www.nozominetworks.com/wp-content/uploads/2021/09/Hardware-Hacking-BLOG-11.jpg)

**Figure 11.** First capture of the logic analyzer. Note that all the channels are set in analog mode.

Figure 11 shows the first capture of the logic analyzer. For this first analysis, all the channels have been set in analog mode, so that we can understand the voltage the memory uses. The vertical red line represents the moment when the device was turned on.

Let’s start doing some tests. From Figure 9a (above pinout schematic), we assume Pin #4 to be the GND: now we have a good confirmation of it, since the channel A3 (Pin #4) is always 0V.

Similarly, Pin #7 and Pin #8 are always 3.3V. This can confirm both that Pin #8 is the VCC and that Pin #7 is the RESET (active low). Note that the sampling frequency of the logic analyzer with eight active channels is too low to see the few cycles delay of the RESET signal.

\[![](https://www.nozominetworks.com/wp-content/uploads/2021/09/Hardware-Hacking-BLOG-12.jpg)

**Figure 12.** Confirmation that the pin #6 is SCLK.

Furthermore, if we set channel 5 (Pin #6) in digital mode, and we zoom into it, we will get what is shown in Figure 12 above. Here, we can confirm that pin number 6 is the SCLK (serial clock) pin.

Now we have enough elements to confirm our hypothesis. Before going on with the actual content reading, let’s do a double check. Most logic analyzer applications offer the capability of debugging a set of protocols, among them SPI.

So, we can feed the SPI protocol analyzer with the information we have up to now (SCLK, RESET, VCC, GND), and those we are now assuming (SI, SO, CS). The write protect signal, like the SI, are inputs, so we cannot detect them as outputs.

\[![](https://www.nozominetworks.com/wp-content/uploads/2021/09/Hardware-Hacking-BLOG-13.jpg)

**Figure 13.** The SPI analyzer tool confirms our guesses!

As we can see from Figure 13 above, the SPI analyzer tool confirms our assumptions. In fact, it can read what the SPI memory is sending out.

Now we are finally ready to read the memory contents and dump the firmware! In the next blog we demonstrate some examples of complete memory dump methodologies based on real use-cases.

You can read Part 2 here: [“Methods for Extracting Firmware from OT Devices for Vulnerability Research.”](https://www.nozominetworks.com/blog/methods-for-extracting-firmware-from-ot-devices-for-vulnerability-research/)

#### Understanding the Interface Signals of the SPI Protocol

Most of the flash memory chips for embedded devices leverage the Serial Peripheral Interface (SPI) as a communication port between the microprocessor or microcontroller and the memory itself. The interface was developed by Motorola in the mid-1980s and has become a standard. It is primarily used for interfacing memories with microprocessors but also for Liquid Digital Displays (LCDs) and many other applications.

SPI devices communicate in full-duplex, with a master-slave architecture where, usually, there is only one master and one or more slaves; the master, also called controller, generates frames for reading and writing. The selected slave, identified with the Chip Select (CS) signal, responds to master requests.

Usually, SPI interfaces present eight signals:

* SCLK: Serial Clock (output from master)
* MOSI: Master Out Slave In (data output from master)
* MISO: Master In Slave Out (data output from slave)
* CS /SS: Chip/Slave Select (output from master)
* VDD: Voltage Drain Drain (to power on the slave device)
* GND: Ground Reference
* HOLD: Hold Signal (for multiple slaves’ communications)
* WP: Write Protect

The WP and the Hold signals are worth a deeper investigation about their meaning and behavior.

The Write Protect signal is used to avoid unintended writing on the memory. If the WP signal is active, the memory content cannot be altered, while if it is not active, the memory can be written or erased. Even if this signal seems to control only the writing/erasing operations, it can also be used to protect the memory from unauthorized reading, so during dumping operations this signal needs to be inactive.

The HOLD signal is used with multiple slave communications. Together with the CS/SS signal, the HOLD signal can be used by the master controller to hold the reading/writing operations except for communications from one slave.

During dumping procedures, this signal must be kept non-active.

![](https://www.nozominetworks.com/wp-content/uploads/2022/01/Extracting-Firmware-Figure-1.jpg)

**Figure 1.** Wiring between an SPI flash memory and a bus interface.

#### Wiring up the Memory Chips for Data Extraction

To establish proper communication between the memory and our PC, we need to use a bus interface (see [Part 1](https://www.nozominetworks.com/blog/extract-firmware-from-ot-devices-for-vulnerability-research/)).

Figure 1 shows the correct wiring between an SPI flash memory and a bus interface. It is important to notice that the MISO and MOSI connections are flipped; in fact, the Master Out becomes the input of the slave (Slave Input) and vice versa.

Furthermore, the WP and the HOLD signal can be connected to both 3V3 (3.3 volts power output, logical 1) or GND (ground reference, logical 0). The datasheet of our target memory helps establish the proper wiring setup of these two signals: in fact, if the WP signal is active high, it must be connected to GND, while if it is active low, it must be connected to 3V3. The same approach is also valid for the HOLD signal.

\[![](https://www.nozominetworks.com/wp-content/uploads/2022/01/Extracting-Firmware-Figure-2b.jpg)**Figure 2a.** A SOIC/SOP test clip connecting the bus interface to a memory chip.**Figure 2b.** Grabbers connecting the bus interface to a memory chip.

To connect the bus interface to the memory chip, both grabbers and SOP/SOIC test clips can be used. Figure 2a shows the usage of a SOIC/SOP test clip, while Figure 2b shows the option of common grabbers.

#### Reading the Flash ROM Data

Everything is ready to start dumping our target memory contents. To do that, software running on our PC is required to correctly handle the SPI communication with the memory. In this blog we will present Flashrom, a software that is able to identify, read, write, verify and erase flash memories. It is an open-source project running on every Unix-based system and supporting a very high number of memory chips.

To check if our target memory is supported by Flashrom, we can look for the chip model in the Flashrom supported hardware list.

\[![](https://www.nozominetworks.com/wp-content/uploads/2022/01/Extracting-Firmware-Figure-3.jpg)

**Figure 3.** The Flashrom supported hardware list identifies that the target memory is supported.

For this example, we will consider the Annke N48PBB Network Video Recorder (NVR), which embeds a `Macronix MXIC MX25L12835F` SPI flash memory.

As we can see in Figure 3, the `MX25L12835F` is supported by Flashrom, so, we can start reading its content.

To correctly read the contents of flash memory, Flashrom needs two important parameters: the bus interface ID and the target memory model.

The programmer ID parameter depends on which bus interface is adopted. In this case we used the Attify Badge, which is based on a FTDI chip communicating with the memory through SPI protocol. In the Flashrom manual, the programmer name for this kind of bus interfaces is `ft2232_spi:type=232H`.

The target memory ID, instead, is the model of the flash memory that can be found in the Flashrom list of supported hardware. From the supported hardware list, we identified the name of the chip we are reading from: `MX25L12835F/MX25L12845E/MX25L12865E`.

The option that enables the setting of the programmer ID is `-p`, while the memory ID is `-c`.

The complete Flashrom command will then be:\
`flashrom -p ft2232_spi:type=232H -c MX25L12835F/MX25L12845E/MX25L12865E -r image.bin`

The `-r` option, on the other hand, tells Flashrom to perform a reading operation.

The output of this command will eventually be a dump of the entire content of the flash chip, which will be saved in file image.bin.

#### A Sample Analysis of a Verkada IP Surveillance Camera

We have just seen how to dump the content of an SPI memory supported by Flashrom. So, how do we deal with memory chips that are not supported by Flashrom?

\[![](https://www.nozominetworks.com/wp-content/uploads/2022/01/Extracting-Firmware-Figure-4.jpg)

**Figure 4.** PCB overview of the Verkada D40 camera.

Let’s consider a Verkada D40 IP surveillance camera, whose PCB is shown in Figure 4. After an exhaustive analysis of the PCB, we can identify a `HeYangTek HYF2GQ4UAACAE` flash memory.\
A deeper investigation into this memory chip highlights three problems:

* The memory has a WSON memory package, so its pins are not easily reachable;
* No manuals or datasheets are available;
* The memory is not officially supported by Flashrom.

\[![](https://www.nozominetworks.com/wp-content/uploads/2022/01/Extracting-Firmware-Fg-5b.jpg)**Figure 5a.** The HeYangTek HYF2GQ4UAACAE mounted on the Verkada D40 PCB.**Figure 5b.** The flash memory desoldered from the PCB.To overcome these problems, we first unsoldered the memory chip from the PCB, soldered a small jumper wire for each pad of the memory and tried to read its content with Flashrom, as we saw before. Since there is not a memory ID for that chip, we tried some common SPI chip IDs, but were not able to read the contents.

At this point, the only way to dump the contents of our target memory is to adopt a dedicated programmer.

\[![.gitbook/assets/1664530465\_5672.png](https://www.nozominetworks.com/wp-content/uploads/2022/01/Extracting-Firmware-Figure-7c.png)**Figure 6a.** The BeeProg2C with the socket adapter for WSON-8 memories.**Figure 6b.** The HeYangTek HYF2GQ4UAACAE flash chip positioned in the socket adapter.**Figure 6c.** The dumping procedure from the flash chip.By searching the memory model on the internet, we were able to find that the BeeProg2C by Elnec is compatible with our target chip; so, we bought one, together with a socket adapter for WSON memory packages.

Figure 6a shows the programmer with the socket adapter plugged into. The HeYangTek memory was put into the socket (Figure 6b). Finally, we were able to read its contents, through the BeeProg2C dedicated software (Figure 6c).
