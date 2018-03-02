import logging
import subprocess
from pyric import pyw

import wishful_module_wifi
import wishful_upis as upis
import wishful_framework as wishful_module
from wishful_framework.classes import exceptions


__author__ = "Michele Segata, Nicolo' Facchi"
__copyright__ = "Copyright (c) 2017, University of Trento"
__version__ = "0.1.0"
__email__ = "{michele.segata,nicolo.facchi}@unitn.it"


def run_command(command):
    '''
    Method to start the shell commands
    and get the output as iterater object
    '''

    sp = subprocess.Popen(command, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, shell=True)
    out, err = sp.communicate()

    if err:
        return [None, "", ""]

    return [sp.returncode, out.decode('utf-8'), err.decode('utf-8')]


@wishful_module.build_module
class PoprowWifiModule(wishful_module_wifi.WifiModule):
    def __init__(self):
        super(PoprowWifiModule, self).__init__()
        self.log = logging.getLogger('PoprowWifiModule')
        self.channel = 1
        self.power = 1
        self.band = "2GHz"

    @wishful_module.bind_function(upis.radio.set_tx_power)
    def set_tx_power(self, tx_power_dbm):
        # disable power saving
        ibss_ps_off_cmd = 'sudo iw dev ' + self.interface + \
                          ' set power_safe off'
        [rcode, sout, serr] = run_command(ibss_ps_off_cmd)
        # then use standard UPI call
        super(PoprowWifiModule, self).set_tx_power(tx_power_dbm)

    @wishful_module.bind_function(upis.wifi.net.start_adhoc)
    def start_adhoc(self, driver, iface, essid, freq, txpower, rate, ip_addr,
                    rts='off', mac_address="aa:bb:cc:dd:ee:ff",
                    skip_reload=False):

        # search for a wifi device that does not have VHT
        intcap = "VHT"

        wifi_int = pyw.winterfaces()
        for wifi_int_name in wifi_int:
            del_cmd = "sudo iw dev " + wifi_int_name + " del"
            [rcode, sout, serr] = run_command(del_cmd)
            self.log.debug("Deleting interface {}".format(wifi_int_name))

        self.band = "2GHz"
        if int(freq) > 3000:
            self.band = "5GHz"

        # Look for a candidate PHY (currently based on frequency and
        # capabilities (HT or VHT) support
        phys = pyw.phylist()
        selected_phy = None

        for phy in phys:
            phy_info = pyw.phyinfo(pyw.Card(phy[0], None, 0))
            if phy_info['bands'].get(self.band) and phy_info.get('modes'):
                if not bool(phy_info['bands'][self.band][intcap]):
                    if 'ibss' in phy_info['modes']:
                        selected_phy = phy
                        break

        # Add and configure mesh and monitor interfaces
        if selected_phy is not None:

            # Create ibss point interface
            ibss_cmd = 'sudo iw phy ' + selected_phy[1] + \
                       ' interface add ' + iface + \
                       ' type ibss'
            [rcode, sout, serr] = run_command(ibss_cmd)
            self.log.debug("Creating interface {} on phy {}".
                           format(iface, selected_phy[1]))

            self.interface = iface

            # Set ibss interface IP address
            ibss_ip_cmd = 'sudo ip addr add ' + ip_addr + \
                          ' dev ' + iface
            [rcode, sout, serr] = run_command(ibss_ip_cmd)
            # TODO: search for UPI
            self.log.debug("Setting IP addr {} to interface {}".
                           format(ip_addr, iface))

            # Add monitor interface
            ibss_mon_cmd = 'sudo iw dev ' + iface + ' interface add ' + \
                           'mon0 type monitor'
            # TODO: search for UPI
            [rcode, sout, serr] = run_command(ibss_mon_cmd)
            self.log.debug("Creating monitor interface mon0 for {}"
                           .format(iface))

            # Bring interfaces up
            ibss_up_cmd = 'sudo ip link set dev ' + iface + ' up'
            [rcode, sout, serr] = run_command(ibss_up_cmd)
            self.log.debug("Bringing interface {} up".format(iface))
            ibss_mon_up_cmd = 'sudo ip link set dev mon0 up'
            [rcode, sout, serr] = run_command(ibss_mon_up_cmd)
            self.log.debug("Bringing interface mon0 up")

            ibss_join_cmd = 'sudo iw dev ' + iface + ' ibss join ' + \
                            essid + ' ' + str(freq) + \
                            ' fixed-freq ' + mac_address + ' beacon-interval ' \
                            + "100"
            [rcode, sout, serr] = run_command(ibss_join_cmd)
            self.log.debug("Joining ad-hoc network {}, frequency {} GHz, "
                           "cell {} with interface {}".
                           format(essid, freq, mac_address, iface))

            self.set_modulation_rate(rate)
            self.set_tx_power(txpower)

    @wishful_module.bind_function(upis.radio.interface_down)
    def interface_down(self):
        if_down_cmd = "sudo ifconfig {} down".format(self.interface)
        [rcode, sout, serr] = run_command(if_down_cmd)
        self.log.debug("Bringing interface {} down".format(self.interface))
