# ipv6gaw
IPv6 Global Address Watcher - For those with bothersome internet providers. This tool is for anyone that has an internet provider that constantly changes their ipv6 prefix. It requires Python 3.6 or greater, and the /sbin/ip command installed on the system. It was wrote after I noticed that using the "ip token" command would fail to update my system's ipv6 address the next time the system got a new valid ipv6 prefix, and I just want to control my system's hostbits.

To use: Update ipv6gaw.json to include the interfaces for the script to watch, and the desired hostbits for the system. For example, if your ISP assigns you a prefix of 2001:0db8:fa57:dead::/64, then what do you want your hostbits to be? Include the IPv6 Prefix length as well. It's almost certainly /64.

Example: '::1234/64' will assign hostbits 1234 to the address resulting in 2001:0db8:fa57:dead::1234.

Then when your isp inexplicably changes the prefix again, your system will update with the desired hostbits. So if it then changes to 2001:0db8:aaaa:f0c1::/64, the system will assign itself 2001:0db8:aaaa:f0c1::1234.

Run the script as root, or as a user that has the privilege to add/remove ip addresses on the system. If sudo is needed to run the /sbin/ip command, then set "use_sudo" to True. An example of a sudoers file that would allow an account (alice in this case) to add/remove ip addresses on the system:

 alice ALL = NOPASSWD: /sbin/ip

Add your custom code to the function do_other_things_on_new_ipv6_assignment. That can be used to process dynamic dns updates, update system routing tables, update downstream ipv6 slaac/dhcpv6 settings, send notifications, etc...

TODO:
*Develop systemd files so that the script can be daemonized.
*Include instructions for a fresh Ubuntu install.
