MULTI Network Manager
=====================

MULTI Network Manager (MNM) is a command line network manager for Linux, with
support for multihoming (currently IPv4 only). It automatically detects new
network interfaces, acquires an IP (using for example DHCP or read from config
file) and configures the routing table(s) accordingly, using
Netlink/RTNetlink-messages.  MNM supports the following command line options:

* -d : Run MNM as daemon. Log-messages are written to /var/log/multi.log.
* -u : Ensure that each interface is assigned a unique IP. Use this one with
  care, as DHCP has no way to gracefully reject an IP address. Instead, DHCP
  DECLINE is used, which causes DHCP servers to blacklist IP addresses.
* -y filename : Provide a configuration file allowing you to specify which
  interfaces shall be assigned a static IP (and the IP of course), as well as 
  static metrics. An example configuration file is in the /examples-directory.

Features
--------
* Automatically detects new network interfaces and configures the routing
  subsystem accordingly.
* Proper multihoming support, the routing configuration is done so that all
  interfaces can be used (unlike the default Linux/ip-behavior).
* Supports specifying static IPs and metrics, using an easy configuration file
  format.
* Broadcasts information about network events. This enables applications to
  easily adapt to changes in network state. The file multi\_netlinkrecv.c in
  /examples shows how this information can be read.

Notes
-----
For MNM to work properly, other network managers (for example GNOME's) must be
disabled. Also, make sure that no dhclient instances are running on any of the
interfaces you want to configure. In order to set interfaces to automatically
come up, but don't get an IP (i.e., for use with MNM), set them to manual in
/etc/network/interfaces. For example:

    iface eth0 inet manual
        up ifconfig $IFACE 0.0.0.0 up
        down ifconfig $IFACE down

If you are going to use MNM with PPP devices, make sure the 'nodefaultroute'
option is specified. MNM will create this route automatically.

Future work
-----------
* IPv6 support: Due to a lack of available IPv6 networks, I have not been able
  to add IPv6 support to MNM. This is on my schedule, but if anyone wants to
  contribute, that would be great.
* Improved error handling: Currently, the user is not notified when for example
  he or she provides an incorrect route. This is due to some tricky message
  handling that I have not decided on how to deal with yet. Some
  RTNETLINK-messages generate replies, while others don't.
* General code clean-up: The application has proven to be stable (used in a scientific
  test network for over a year now) and without memory leaks, but the overall
  structure still bears the marks of mostly being written during a PhD.

Motivation
----------
Linux supports multihoming, however, when a Linux-device is connected to
multiple networks simultaneously, the kernel will often be unable to make a
routing decision due to overlapping routes. 

The most common technique for configuring the routing subsystem in the presence
of multiple active interfaces, is to use scripts. This is a static and error
prone process, that does not scale. For example, scripts and route metrics needs
to be updated as new interfaces are added.

While working on my PhD, I had to make several experiments on multihomed hosts
with different number of active network interfaces. After I had made one to many
configuration mistakes with my setup scripts, I decided to write MNM.

Contact
-------

If you have any questions, comments or just want to say hi, please contact me at
kristian.evensen@gmail.com.
