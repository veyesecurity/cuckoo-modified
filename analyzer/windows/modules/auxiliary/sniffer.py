# Copyright (C) 2015 vEyE Security Ltd., Yevgeniy Kulakov (yevgeniy@veye-security.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import time
import os
import logging
from threading import Thread
import subprocess

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

class Sniffer(Auxiliary, Thread):
    """Launch a sniffer process."""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.do_run = True
        self.started = False
        self.proc = None
        self.netdump = ""
        
    def stop(self):
        self.do_run = False
        log.info("Stopping sniffer.")
        if self.proc:
            self.proc.terminate()
            if len(self.netdump) > 0:
                log.info("Uploading pcap file.")
                upload_to_host(self.netdump, "files/dump.pcap", False)

    def run(self):
        tcpdump = os.path.join(os.getenv("TEMP"), "mon.exe")
        log.info("Sniffer located at: %s" % tcpdump)
        self.netdump = os.path.join(os.getenv("TEMP"), "dump.pcap")
        log.info("Pcap file at: %s" % self.netdump)

        if not tcpdump:
            log.info("Sniffer was not found.")
            return True

        while self.do_run:
            time.sleep(1)
            if self.started == False:
                pargs = [tcpdump, "-U", "-s", "0", "-n", "-w", self.netdump]
                try:
                    self.proc = subprocess.Popen(pargs)
                    if self.proc:
                        log.info("Started sniffing to file.")
                        self.started = True
                    else:
                        log.info("Sniffer didn't start.")
                except (OSError, ValueError):
                    log.exception("Failed to start sniffer.")
                    return
                
