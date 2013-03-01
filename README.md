MULTI Network Manager
=====================

MULTI Network Manager (MNM) is a command line network manager for Linux, with
support for multihoming. It automatically detects new network interfaces,
acquires an IP (using for example DHCP or read from config file) and configures
the routing table(s) accordingly, using Netlink-messages. MNM supports the
following command line options:

* -d : Run MNM as daemon. Log-messages are written to /var/log/multi.log.
* -u : Ensure that each interface is assigned a unique IP. Use this one with
  care, as DHCP has no way to gracefully reject an IP address. Instead, DHCP
  DECLINE is used, which causes DHCP servers to blacklist IP addresses.
* -y <filename> : Provide a configuration file allowing you to specify which
  interfaces shall be assigned a static IP (and the IP of course), as well as 
  static metrics. An example configuration file is in the /examples-directory.

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


Today, when a Linux-device is connected to multiple
networks simultaneously, the kernel will often be unable to make a routing
decision due to overlapping routes.
