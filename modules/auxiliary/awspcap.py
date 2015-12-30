# Copyright (C) 2015 vEyE Security Ltd., Yevgeniy Kulakov (yevgeniy@veye-security.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import stat
import logging
import subprocess
import shutil

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.config import Config

log = logging.getLogger(__name__)

class AWSpcap(Auxiliary):
    def start(self):
        return

    def stop(self):

        src_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % self.task.id, "files", "dump.pcap")
        dst_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % self.task.id, "dump.pcap")

        if os.path.exists(src_path):
            shutil.copy2(src_path, dst_path)
            log.debug("PCAP copied to task root directory.")
        else:
        	log.debug("Failed to locate PCAP file.")

        return
