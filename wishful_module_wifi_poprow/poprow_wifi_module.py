import logging
import random
import pickle
import os
import inspect
import subprocess
import zmq
import time
import platform
import numpy as np
import iptc
from pyric import pyw
from pytc.TrafficControl import TrafficControl

import wishful_module_wifi
import wishful_upis as upis
import wishful_framework as wishful_module
from wishful_framework.classes import exceptions
import wishful_framework.upi_arg_classes.edca as edca #<----!!!!! Important to include it here; otherwise cannot be pickled!!!!
import wishful_framework.upi_arg_classes.flow_id as FlowId


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

    @wishful_module.bind_function(upis.radio.set_per_flow_tx_power)
    def set_per_flow_tx_power(self, flowId, txPower):
        self.log.debug('set_per_flow_tx_power on iface: {}'.format(self.interface))

        tcMgr = TrafficControl()
        markId = tcMgr.generateMark()
        self.setMarking(flowId, table="mangle", chain="POSTROUTING", markId=markId)

        cmd_str = ('sudo iw ' + self.interface + ' info')
        cmd_output = subprocess.check_output(cmd_str, shell=True, stderr=subprocess.STDOUT)

        for item in cmd_output.split("\n"):
             if "wiphy" in item:
                line = item.strip()

        phyId = [int(s) for s in line.split() if s.isdigit()][0]

        try:
            myfile = open('/sys/kernel/debug/ieee80211/phy'+str(phyId)+'/ath9k/per_flow_tx_power', 'w')
            value = str(markId) + " " + str(txPower) + " 0"
            myfile.write(value)
            myfile.close()
            return "OK"
        except Exception as e:
            self.log.fatal("Operation not supported: %s" % e)
            raise exceptions.UPIFunctionExecutionFailedException(func_name='radio.set_per_flow_tx_power', err_msg='cannot open file')


    def setMarking(self, flowId, table="mangle", chain="POSTROUTING", markId=None):
        
        if not markId:
            tcMgr = TrafficControl()
            markId = tcMgr.generateMark()

        rule = iptc.Rule()

        if flowId.srcAddress:
            rule.src = flowId.srcAddress

        if flowId.dstAddress:
            rule.dst = flowId.dstAddress

        if flowId.prot:
            rule.protocol = flowId.prot
            match = iptc.Match(rule, flowId.prot)

            if flowId.srcPort:
                match.sport = flowId.srcPort

            if flowId.dstPort:
                match.dport = flowId.dstPort

            rule.add_match(match)

        target = iptc.Target(rule, "MARK")
        target.set_mark = str(markId)
        rule.target = target
        chain = iptc.Chain(iptc.Table(table), chain)
        chain.insert_rule(rule)


    @wishful_module.bind_function(upis.radio.clean_per_flow_tx_power_table)
    def clean_per_flow_tx_power_table(self):
        self.log.debug('clean_per_flow_tx_power_table on iface: {}'.format(self.interface))

        cmd_str = ('sudo iw ' + self.interface + ' info')
        cmd_output = subprocess.check_output(cmd_str, shell=True, stderr=subprocess.STDOUT)

        for item in cmd_output.split("\n"):
             if "wiphy" in item:
                line = item.strip()

        phyId = [int(s) for s in line.split() if s.isdigit()][0]

        try:
            myfile = open('/sys/kernel/debug/ieee80211/phy'+str(phyId)+'/ath9k/per_flow_tx_power', 'w')
            value = "0 0 0"
            myfile.write(value)
            myfile.close()
            return "OK"
        except Exception as e:
            self.log.fatal("Operation not supported: %s" % e)
            raise exceptions.UPIFunctionExecutionFailedException(func_name='radio.clean_per_flow_tx_power_table', err_msg='cannot open file')

    @wishful_module.bind_function(upis.radio.get_per_flow_tx_power_table)
    def get_per_flow_tx_power_table(self):
        self.log.debug('get_per_flow_tx_power_table on iface: {}'.format(self.interface))

        cmd_str = ('sudo iw ' + self.interface + ' info')
        cmd_output = subprocess.check_output(cmd_str, shell=True, stderr=subprocess.STDOUT)

        for item in cmd_output.split("\n"):
             if "wiphy" in item:
                line = item.strip()

        phyId = [int(s) for s in line.split() if s.isdigit()][0]

        try:
            myfile = open('/sys/kernel/debug/ieee80211/phy'+str(phyId)+'/ath9k/per_flow_tx_power', 'r')
            data = myfile.read()
            myfile.close()
            return data
        except Exception as e:
            self.log.fatal("Operation not supported: %s" % e)
            raise exceptions.UPIFunctionExecutionFailedException(func_name='radio.get_per_flow_tx_power_table', err_msg='cannot open file')

    @wishful_module.bind_function(upis.radio.set_tx_power)
    def set_tx_power(self, tx_power_dbm):
        # disable power saving
        ibss_ps_off_cmd = 'sudo iw dev ' + self.interface + ' set power_safe ' \
                                                            'off'
        [rcode, sout, serr] = run_command(ibss_ps_off_cmd)
        # then use standard UPI call
        super(PoprowWifiModule, self).set_tx_power(tx_power_dbm)

        # cmd_str = 'sudo iw dev ' + self.interface + ' set txpower fixed ' +\
        #             str(tx_power_dbm * 100)
        # run_command(cmd_str)

    @wishful_module.bind_function(upis.wifi.net.start_adhoc)
    def start_adhoc(self, driver, iface, essid, freq, txpower, rate, ip_addr,
                    rts='off', mac_address="aa:bb:cc:dd:ee:ff",
                    skip_reload=False):

        # search for a wifi device that only has HT and not VHT
        intcap = "HT"

        wifi_int = pyw.winterfaces()
        for wifi_int_name in wifi_int:
            del_cmd = "sudo iw dev " + wifi_int_name + " del"
            [rcode, sout, serr] = run_command(del_cmd)
            print(del_cmd)

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
                if bool(phy_info['bands'][self.band][intcap]):
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
            print(ibss_cmd)

            self.interface = iface

            # Set ibss interface IP address
            ibss_ip_cmd = 'sudo ip addr add ' + ip_addr + \
                          ' dev ' + iface
            print(ibss_ip_cmd)
            [rcode, sout, serr] = run_command(ibss_ip_cmd)

            # Add monitor interface
            ibss_mon_cmd = 'sudo iw dev ' + iface + ' interface add ' + \
                           iface + 'mon type monitor'
            print(ibss_mon_cmd)
            [rcode, sout, serr] = run_command(ibss_mon_cmd)

            # Bring interfaces up
            ibss_up_cmd = 'sudo ip link set dev ' + iface + ' up'
            print(ibss_up_cmd)
            [rcode, sout, serr] = run_command(ibss_up_cmd)
            ibss_mon_up_cmd = 'sudo ip link set dev ' + iface + 'mon up'
            print(ibss_mon_up_cmd)
            [rcode, sout, serr] = run_command(ibss_mon_up_cmd)

            # ibss_chan_cmd = 'iw dev ' + args.ibssiname + ' set channel ' +\
            #                 str(args.chan)
            # print(ibss_chan_cmd)
            # [rcode, sout, serr] = run_command(ibss_chan_cmd)

            ibss_join_cmd = 'sudo iw dev ' + iface + ' ibss join ' + \
                            essid + ' ' + str(freq) + \
                            ' fixed-freq ' + mac_address + ' beacon-interval ' \
                            + "100"
            print(ibss_join_cmd)
            [rcode, sout, serr] = run_command(ibss_join_cmd)

            self.set_modulation_rate(rate)
            self.set_tx_power(txpower)

