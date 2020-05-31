#!/usr/bin/env python3
# -*- coding: utf-8 -*

"""
IPv6 Global Address Watcher. This is a script that keeps global IPv6 addresses consistent. The circumstances for
using this script are:
A) The system has interface(s) that will only have a single global IPv6 prefix.
B) The system is on a network with an ISP / Network Provider that changes that interface's IPv6 prefix often.
C) The server admin would like the system to have a consistent IPv6 address (hostbits) despite those circumstances.

Must have the ip command installed! typically located at /sbin/ip. Also must have permission to add and remove ip
addresses from the system.

The "ip token set" command, which normally is intended for this scenario, doesn't update when ISP frequently changes
the IPv6 prefix. Also, this script will delete all of the old global ipv6 addresses when a new prefix is assigned if
configured to do so; therefore, there is no chance the system keeps wrongly using the old prefixes and encounters
unnecessary downtime.

The basic overview of the script is that it starts the "ip monitor address" command and watches for new ipv6 address
assignments. If it sees a new ipv6 address that also has a new ipv6 prefix (detected by the valid lifetime) it will
assign a new ipv6 address with the new prefix and token (hostbits) configured in class Settings, and purge all global
ipv6 addresses with the old prefix, assumed to be invalid because of the new prefix.

It will not remove any additional addresses the server assigns such as addresses from privacy extensions or EUI-64, nor
will it affect IPv6 addresses that aren't global, such as ULA or link-local addresses.
"""
try:
    import sys
    import os
    import logging
    import time
    import subprocess
    import select
    import ipaddress
    import json
except ImportError as e:
    logging.error("Could not import a module! Please ensure all libraries are installed.",
                  exc_info=True)
    sys.exit(1)


__author__ = "Ryan Richter"
__copyright__ = "Copyright 2020"
__credits__ = ["Ryan Richter", ]
__license__ = "MIT"
__version__ = "0.618034"
__maintainer__ = "Ryan Richter"
__email__ = "ryan@techyoshi.com"
__status__ = "Pre-git"


class Settings:
    # Initialization
    log = logging.getLogger('ipv6globaladdressmonitor')
    set_log_level = False
    config_file = ""
    config = {}
    _ip_command = "/sbin/ip"
    if __name__ == "__main__":
        import argparse
        parser = argparse.ArgumentParser(description="IPv6 Global Address Monitor.")
        parser.add_argument("-c", "--config", help="JSON Config File to Use")
        parser.add_argument("-v", "--verbose",
                            help="Sets logging level to logging.DEBUG instead of logging.INFO", action='store_true')
        cmdargs = parser.parse_args()
        if cmdargs.verbose:
            log.setLevel(logging.DEBUG)
        else:
            log.setLevel(logging.INFO)
        set_log_level = True
        if cmdargs.config:
            config_file = cmdargs.config
        if not set_log_level:
            log.setLevel(logging.INFO)
            set_log_level = True
        if not config_file:
            _config_file_name = "ipv6gaw.json"
            _config_file_locations = [
                os.path.join(os.getcwd(), _config_file_name),
                os.path.join(os.path.expanduser("~"), ".config", "."+_config_file_name),
                os.path.join("/etc/", _config_file_name),
            ]
        else:
            _config_file_locations = [config_file]
        for _config_file_location in _config_file_locations:
            try:
                with open(_config_file_location, "r") as f:
                    config = json.loads(f.read())
                break
            except FileNotFoundError as e:
                continue
            except json.JSONDecodeError as e:
                raise UserWarning(
                    f"Could not read configuration file {_config_file_location}"
                )
        else:
            raise UserWarning(
                f"No Settings File was found. Please specify config file with -c or create one in a default directory.",
            )
    if not set_log_level:
        log.setLevel(logging.WARNING)
        set_log_level = True
    if not config:
        logging.warning("You may need to define settings in ipv6gaw.Settings.config prior to use via import.")
    def _which_ip_command() -> list:
        return [Settings._ip_command, "monitor", "address"]
    def _list_ip_command(interface: str) -> list:
        return [Settings._ip_command, "addr", "show", interface]
    def _add_ip_command(ip_address: str, interface: str) -> list:
        cmdsudo = []
        if Settings.config["Settings"]["use_sudo"]:
            cmdsudo = ["sudo"]
        return cmdsudo + [Settings._ip_command, "addr", "add", ip_address, "dev", interface]
    def _del_ip_command(ip_address: str, interface: str) -> list:
        cmdsudo = []
        if Settings.config["Settings"]["use_sudo"]:
            cmdsudo = ["sudo"]
        return cmdsudo + [Settings._ip_command, "addr", "del", ip_address, "dev", interface]


def poll_ip_monitor(time_sleep=1):
    """
    Starts a process to monitor ip addresses "ip monitor command"
    :param time_sleep: how long to sleep between checking output on the monitor_ip_command.
    :return:
    """
    f = subprocess.Popen(
        Settings._which_ip_command(),
        encoding="utf8",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    p = select.poll()
    p.register(f.stdout)
    while True:
        if p.poll(1):
            process_new_ip_monitor_line(f.stdout.readline())
        time.sleep(time_sleep)


def process_new_ip_monitor_line(logline: str):
    """
    Monitor for new IPv6 Address Assignments
    :param logline: line from ip monitor command
    :return:
    """
    # ip monitor command shows new ipv6 assignments like this:
    # 4: eth0    inet6 2001:0db8:fa57:dead::1357:9bdf/64 scope global dynamic mngtmpaddr noprefixroute
    # Check if log line has the keywords in it that indicate a new ipv6 address have been assigned.
    # Keywords that we check for are: interface "inet6" "scope" "global"
    interfaces = Settings.config["Settings"]["interfaces_to_watch"]
    if any(
            all(x in logline for x in [interface, "inet6", "scope", "global"])
            for interface
            in interfaces
        ):
        # Pull out the interface that was found in this log line, and then review ipv6 addresses
        ipv6_int_str = logline.split("inet6")[0].split()[-1].lstrip().rstrip()
        logging.debug("This line was seen that appears to be a new IPv6 assignment: \n{0}\n".format(
                          logline,
                      ) + " Proceeding with reviewing IPv6 addresses."
                      )
        review_and_update_ipv6_addresses(ipv6_int_str)
        # print(f"I see you: {ipv6_int_str}")


def review_and_update_ipv6_addresses(interface: str) -> tuple:
    """
    Reviews all global IPv6 addresses, and assigns a new IPv6 address with the correct hostbits (token) if a new prefix
    was found. Removes old IPv6 addresses with obsolete prefixes so the OS no longer uses them as well.
    This is accomplished by listing all IPv6 addresses, then finding the one with the largest lifetime.
    The function assumes that the IPv6 address with the biggest lifetime has the valid global IPv6 prefix. In typical
    situations, this will always be the case. However, in the event either ISP or router changes the router
    advertisements to use a different valid lifetime value, this script may behave incorrectly. Also, I recommend your
    network has IPv6 snooping setup so your server isn't vulnerable from picking up a bad prefix from a malicious host,
    something you should do regardless if you run this script or not.
    :param interface: interface that is being reviewed
    :return: tuple (ipaddress.IPv6Interface, bool) (
        Assigned IPv6 address with correct hostbits (token),
        if the assignment was new
    )
    """
    class LINE_ITERATOR_MODES:
        mode_checking_for_inet6_addr = 0
        mode_checking_for_lifetime_values = 1
    # List the IP addresses from the interface so that we can get their lifetimes
    logging.debug("Getting ip address list.")
    ip_addr_stdout = subprocess.run(
        Settings._list_ip_command(interface=interface),
        stdout=subprocess.PIPE,
    ).stdout
    # Iterate through the lines of output from ip addr command to get inet6 addresses and information.
    inet6s = {}
    inet6 = ""
    line_iterator_mode = LINE_ITERATOR_MODES.mode_checking_for_inet6_addr
    logging.debug("Parsing line-by-line the output of the IP address list" +
                  " and pulling out inet6 addresses with their lifetimes.")
    for line in ip_addr_stdout.decode().splitlines():
        if line_iterator_mode == LINE_ITERATOR_MODES.mode_checking_for_inet6_addr:
            # Standard output if the ip addr show command has IPv6 address lines start with "    inet6"
            if "    inet6" in line:
                inet6 = line.split()[1]
                # found an inet6, change iterator mode to get the lifetime values
                line_iterator_mode = LINE_ITERATOR_MODES.mode_checking_for_lifetime_values
        elif line_iterator_mode == LINE_ITERATOR_MODES.mode_checking_for_lifetime_values:
            # Standard output for lifetime is "       valid_lft 145961sec preferred_lft 0sec"
            inet6_netaddr = ipaddress.ip_interface(inet6)
            is_global = inet6_netaddr.is_global
            # For this script's sake, consider any address with no lifetime the same as if the lifetime is 0.
            if line.split()[1] == "forever":
                valid_lft = 0
                preferred_lft = 0
            else:
                valid_lft = int(line.split()[1].replace("sec", ""))
                preferred_lft = int(line.split()[3].replace("sec", ""))
            # Add the IPv6 address to a dictionary keyed by ip with useful information in the value.
            inet6s[inet6] = (inet6_netaddr, is_global, valid_lft, preferred_lft)
            # Go back to checking for more inet6 addresses
            line_iterator_mode = LINE_ITERATOR_MODES.mode_checking_for_inet6_addr
    # Find the IPv6 address that is a global address and has the biggest valid lifetime
    logging.debug("Here are the IPv6 addresses I see: {}".format(str(inet6s)))
    current_valid_ipv6, current_valid_ipv6_info = max(
        [(k, inet6s[k]) for k in inet6s.keys() if inet6s[k][1] is True],
        key=lambda x: (inet6s[x[0]][2])
    )
    logging.debug("Here is the IPv6 address with the longest valid lifetime: {0}".format(str(current_valid_ipv6)))
    # Calculate wanted ipv6 address with network bits
    inet6_to_add_address = current_valid_ipv6_info[0].network.network_address + \
                             int(ipaddress.ip_interface(Settings.config["Settings"]["ipv6_token"][interface]))
    assigned_ipv6_check = [
        inet_tuple[0]
        for inet_tuple
        in inet6s.values()
        if inet_tuple[0].ip == inet6_to_add_address
    ]
    if bool(assigned_ipv6_check):
        # The expected IPv6 address has been found. No further action needed.
        logging.debug("Expected IPv6 address {0} already assigned on interface {1}.".format(
            str(inet6_to_add_address),
            interface,
        ))
        return (assigned_ipv6_check[0], False)
    else:
        # Use the IPv6 address with the longest valid lifetime and get its prefix
        logging.info("Expected IPv6 address {0} not found on interface {1}.".format(
            str(inet6_to_add_address),
            interface,
        )+" It seems a new prefix was assigned! Proceeding with update logic.")
        inet6_to_add_prefix = current_valid_ipv6_info[0].network
        inet6_to_add_interface = ipaddress.ip_interface(str(inet6_to_add_address) + \
                                       "/" + str(inet6_to_add_prefix.prefixlen))
        inet6_to_delete = []
        inet6_to_add = str(inet6_to_add_interface)
        # Check all assigned ipv6 addresses to determine which ones now have invalid global prefixes.
        # Add them to a list to delete.
        if Settings.config["Settings"]["delete_obsolete_prefixes"]:
            for inet, inet_tuple in inet6s.items():
                # Only affect global prefixes
                if inet_tuple[1]:
                    # Only delete addresess that aren't in the current global prefix for deletion.
                    if inet_tuple[0].ip not in inet6_to_add_prefix:
                        inet6_to_delete.append(str(inet_tuple[0]))
        # Add the new global address
        new_ip_addr = subprocess.run(
            Settings._add_ip_command(ip_address=inet6_to_add, interface=interface),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if new_ip_addr.returncode != 0:
            raise UserWarning(new_ip_addr.stderr.decode())
        # Remove the obsolete global addresses
        for inet6 in inet6_to_delete:
            del_ip_addr = subprocess.run(
                Settings._del_ip_command(ip_address=inet6, interface=interface),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if del_ip_addr.returncode != 0:
                raise UserWarning(del_ip_addr.stderr.decode())
        do_other_things_on_new_ipv6_assignment(inet6_to_add_interface, interface)
        return (inet6_to_add_interface, True)


def do_other_things_on_new_ipv6_assignment(inet6_added: ipaddress.IPv6Interface, interface: str):
    """
    Perform other actions when a new ipv6 address was assigned on an interface.
    For example, process dynamic dns updates, update system routing tables, update
    downstream ipv6 slaac/dhcpv6 settings, send notifications, etc...
    Put your custom code here! By default this does nothing
    :param inet6_added: The new IPv6 address that was assigned
    :param interface: The interface the new IPv6 address was assigned on
    :return:
    """
    pass


def main():
    # Review ipv6 addresses on the host to see if updates need to be done right away
    logging.debug("Reviewing all of the IPv6 addresses on the system now.")
    for interface in Settings.config["Settings"]["interfaces_to_watch"]:
        review_and_update_ipv6_addresses(interface)
    # Start the IP Monitoring Process
    logging.debug("Starting monitoring process now.")
    poll_ip_monitor()


if __name__ == "__main__":
    main()
