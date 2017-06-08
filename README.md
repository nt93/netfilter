# netfilter
A sample firewall Kernel Module in C

README FILE
————————————

Introduction
—————————————
The code that accompanies this README implements a sample firewall kernel module in C.

Files
——————

firewall.c - this file contains the source code of the kernel module.

Makefile - the Makefile necessary to build the kernel module

System/Requirements
————————————————————
This software has been built and tested on a VM within an ExoGENI slice
that leveraged the imaged "Ubuntu 14.04" with machine XO Small.


The output of uname -a on the system is as follows:

root@gateway:~# uname -a
Linux gateway 3.13.0-68-generic #111-Ubuntu SMP Fri Nov 6 18:17:06 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux


Building
——————————
To build the firewall simply change into the directory with the firewall.c
source file and accompanying Makefile and execute the following:
# sudo apt-get update
# sudo apt-get install build-essential
# make


Running/Installing
————————————————————
The firewall.ko kernel module can be installed using insmod as follows:

# insmod firewall.ko

You can verify that the module has been loaded by examining /var/log/messages
for a message indicating that the module was loaded or you can see if it
is loaded as follows:

# lsmod | grep -i firewall


Uninstalling
——————————————
You can remove the module from the kernel as follows:

# rmmod firewall
