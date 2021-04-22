# AsIo3Unlock
## ASUSTeK AsIO3 I/O driver unlock

# Purpose

This is proof-of-concept bypass of pseudo-security caller check implemented in AsIO3, "unlocking" this driver for usage with FULL R/W access. AsIO3 is an "giveio" type driver based on WINIO sources (for reference https://github.com/hfiref0x/Misc/tree/master/source/WormholeDrivers/WINIO). This source code is full of by design bugs/vulnerabilities and used by various HW vendors mostly in unmodified state. Which mean they all share the same platform full of bugs and vulnerabilities. There is a multiple CVE's addressing multiple variants of AsIo driver in past however AsIo developers (presumable this is EneTech company) always IGNORE all reports and only do changes to the driver to COMPLICATE it usage by 3rd party. Which of course does not fix anything and only add more bugs.

# Disclaimer

Using this program might crash your computer with BSOD. Compiled binary and source code provided AS-IS in hope it will be useful BUT WITHOUT WARRANTY OF ANY KIND. Make sure you understand what you do.

# Authors

(c) 2021 AsIo3Unlock Project