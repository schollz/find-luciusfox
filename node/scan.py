#!/usr/bin/python3

# Copyright 2015-2017 Zack Scholl. All rights reserved.
# Use of this source code is governed by a AGPL
# license that can be found in the LICENSE file.

import sys
import json
import socket
import time
import subprocess
import os
import glob
import argparse
import logging
import statistics
import atexit
import serial

logger = logging.getLogger('scan.py')

import requests

class BaseScan:
    def __init__(self, timeout):
        self.timeout = timeout

    def get_payload(self, fingerprints):
        # Compute medians
        fingerprints2 = []
        for mac in fingerprints:
            if len(fingerprints[mac]) == 0:
                continue
            print(mac)
            print(fingerprints[mac])
            fingerprints2.append(
                {"mac": mac, "rssi": int(statistics.median(fingerprints[mac]))})

        logger.debug("Found %d fingerprints" % len(fingerprints2))

        payload = {
            "node": socket.gethostname(),
            "signals": fingerprints2,
            "timestamp": int(
                time.time())}
        logger.debug(payload)
        return payload


class SerialScan(BaseScan):
    """
    Class to implement mac/rssi finding via a serial device that outputs
    periodic list of mac/rssi.

    Protocol is to pass lines in the format of "mac_address rssi packet_count"
    at 115200bps.
    """
    def __init__(self, interface, timeout):
        BaseScan.__init__(self, timeout)

        self.interface = interface

    def do_scan(self):
        # Sleep then read all the data non-blocking until nothing left.
        # Hopefully the internal buffers are big enough to hold it all.
        ser = serial.Serial("/dev/%s" % self.interface, baudrate = 115200, timeout = 0);
        time.sleep(self.timeout)
        inp = ''
        while True:
            read = ser.read(10000)
            if len(read) == 0:
                break;
            inp += str(read, encoding='ascii')
        ser.close();

        fingerprints = {}
        for line in inp.splitlines():
            if line.startswith("-"):
                continue

            mac, rssi, packets = line.split(" ")
            if mac not in fingerprints:
                fingerprints[mac] = []

            for i in range(0, int(packets)):
                fingerprints[mac].append(float(rssi))

        return self.get_payload(fingerprints)


class WifiScan(BaseScan):
    """
    Class to implement mac/rssi finding via a tshark scan of a device in
    monitor mode
    """
    def __init__(self, interface, timeout, single_wifi):
        BaseScan.__init__(self, timeout)

        atexit.register(self.exit_handler)
        self.single_wifi = single_wifi
        self.interface = interface

    def do_scan(self):
        if self.single_wifi:
            logger.debug("Stopping scan...")
            if self.tshark_is_running():
                self.stop_scan()
            logger.debug("Stopping monitor mode...")
            self.restart_wifi()
            logger.debug("Restarting WiFi in managed mode...")

        if not self.tshark_is_running():
            self.start_scan()

        time.sleep( self.timeout )
        return self.process_scan()

    def exit_handler(self):
        print("Exiting...stopping scan..")
        os.system("pkill -9 tshark")

    def restart_wifi(self):
        os.system("/sbin/ifdown --force wlan0")
        os.system("/sbin/ifup --force wlan0")
        os.system("iwconfig wlan0 mode managed")
        while True:
            ping_response = subprocess.Popen(
                ["/bin/ping", "-c1", "-w100", "lf.internalpositioning.com"], stdout=subprocess.PIPE).stdout.read()
            if '64 bytes' in ping_response.decode('utf-8'):
                break
            time.sleep(1)


    def process_scan(self):
        logger.debug("Reading files...")
        output = ""
        maxFileNumber = -1
        fileNameToRead = ""
        for filename in glob.glob("/tmp/tshark-temp*"):
            fileNumber = int(filename.split("_")[1])
            if fileNumber > maxFileNumber:
                maxFileNumber = fileNumber
                fileNameToRead = filename

        logger.debug("Reading from %s" % fileNameToRead)
        cmd = subprocess.Popen(("tshark -r "+fileNameToRead+" -T fields -e frame.time_epoch -e wlan.sa -e wlan.bssid -e radiotap.dbm_antsignal").split(
        ), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output += cmd.stdout.read().decode('utf-8')

        timestamp_threshold = float(time.time()) - float(self.timeout)
        fingerprints = {}
        relevant_lines = 0
        for line in output.splitlines():
            try:
                timestamp, mac, mac2, power_levels = line.split("\t")

                if mac == mac2 or float(timestamp) < timestamp_threshold or len(mac) == 0:
                    continue

                relevant_lines+=1
                rssi = power_levels.split(',')[0]
                if len(rssi) == 0:
                    continue

                if mac not in fingerprints:
                    fingerprints[mac] = []
                fingerprints[mac].append(float(rssi))
            except:
                pass
        logger.debug("..done (%d lines of which %d were relevant)" % (len(output.splitlines)(), relevant_lines))

        return self.get_payload(fingerprints)

    def tshark_is_running(self):
        ps_output = subprocess.Popen(
            "ps aux".split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ps_stdout = ps_output.stdout.read().decode('utf-8')
        isRunning = 'tshark' in ps_stdout and '[tshark]' not in ps_stdout
        logger.debug("tshark is running: " + str(isRunning))
        return isRunning


    def start_scan(self):
        # Remove previous files
        for filename in glob.glob("/tmp/tshark-temp*"):
            os.remove(filename)
        subprocess.Popen(("/usr/bin/tshark -I -i " + self.interface + " -b files:4 -b filesize:1000 -w /tmp/tshark-temp").split(),
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if self.tshark_is_running():
            logger.info("Starting scan")


    def stop_scan(self):
        os.system("pkill -9 tshark")
        if not self.tshark_is_running():
            logger.info("Stopped scan")


def num_wifi_cards():
    cmd = 'iwconfig'
    p = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
    output = p.stdout.read().decode('utf-8')
    return output.count("wlan")

def main():
    # Check if SUDO
    # http://serverfault.com/questions/16767/check-admin-rights-inside-python-script
    if os.getuid() != 0:
        print("you must run sudo!")
        return

    # Check which interface
    # Test if wlan0 / wlan1
    default_wlan = "wlan1"
    default_single_wifi = False
    if num_wifi_cards() == 1:
        default_single_wifi = True
        default_wlan = "wlan0"

    # Parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--group", default="", help="group name")
    parser.add_argument(
        "-i",
        "--interface",
        default=default_wlan,
        help="Interface or tty to listen on - default %s" % default_wlan)
    parser.add_argument(
        "-t",
        "--time",
        default=10,
        help="scanning time in seconds (default 10)")
    parser.add_argument(
        "--single-wifi",
        default=default_single_wifi,
        action="store_true",
        help="Engage single-wifi card mode?")
    parser.add_argument(
        "-s",
        "--server",
        default="https://lf.internalpositioning.com",
        help="send payload to this server")
    parser.add_argument("-n", "--nodebug", action="store_true")
    args = parser.parse_args()

    # Check arguments for group
    if args.group == "":
        print("Must specify group with -g")
        sys.exit(-1)

    # Check arguments for logging
    loggingLevel = logging.DEBUG
    if args.nodebug:
        loggingLevel = logging.ERROR
    logger.setLevel(loggingLevel)
    fh = logging.FileHandler('scan.log')
    fh.setLevel(loggingLevel)
    ch = logging.StreamHandler()
    ch.setLevel(loggingLevel)
    formatter = logging.Formatter(
        '%(asctime)s - %(funcName)s:%(lineno)d - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)
    logger.addHandler(fh)
    logger.addHandler(ch)

    # Startup scanning
    print("Using server " + args.server)
    logger.debug("Using server " + args.server)
    print("Using group " + args.group)
    logger.debug("Using group " + args.group)

    if args.interface.startswith("ttyS"):
        scanner = SerialScan(args.interface, float(args.time))
    else:
        scanner = WifiScan(args.interface, float(args.time), args.single_wifi)

    while True:
        try:
            payload = scanner.do_scan()
            payload['group'] = args.group
            if len(payload['signals']) > 0:
                r = requests.post(
                    args.server +
                    "/reversefingerprint",
                    json=payload)
                logger.debug(
                    "Sent to server with status code: " + str(r.status_code))
        except Exception:
            logger.error("Fatal error in main loop", exc_info=True)

if __name__ == "__main__":
    main()
