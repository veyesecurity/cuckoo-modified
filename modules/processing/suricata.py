# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import time

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import convert_to_printable

log = logging.getLogger(__name__)
class Suricata(Processing):
    """Suricata processing."""
    def cmd_wrapper(self,cmd):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout,stderr = p.communicate()
        return (p.returncode, stdout, stderr)

    def run(self):
        """Run Suricata.
        @return: hash with alerts
        """
        self.key = "suricata"
        # General
        SURICATA_CONF = self.options.get("conf", None)
        SURICATA_EVE_LOG = self.options.get("evelog", None)
        SURICATA_ALERT_LOG = self.options.get("alertlog", None)
        SURICATA_TLS_LOG = self.options.get("tlslog", None)
        SURICATA_HTTP_LOG = self.options.get("httplog", None)
        SURICATA_SSH_LOG = self.options.get("sshlog", None)
        SURICATA_DNS_LOG = self.options.get("dnslog", None)
        SURICATA_FILE_LOG = self.options.get("fileslog", None)
        SURICATA_FILES_DIR = self.options.get("filesdir", None)
        SURICATA_RUNMODE = self.options.get("runmode", None)
        SURICATA_FILE_BUFFER = self.options.get("buffer", 8192)
        Z7_PATH = self.options.get("7zbin", None)
        FILES_ZIP_PASS = self.options.get("zippass", None)
        SURICATA_FILE_COPY_DST_DIR = self.options.get("file_copy_dest_dir", None)
        SURICATA_FILE_COPY_MAGIC_RE = self.options.get("file_magic_re", None)
        if SURICATA_FILE_COPY_MAGIC_RE:
            try:
                SURICATA_FILE_COPY_MAGIC_RE = re.compile(SURICATA_FILE_COPY_MAGIC_RE)
            except:
                log.warning("Failed to compile suricata copy magic RE" % (SURICATA_FILE_COPY_MAGIC_RE))
                SURICATA_FILE_COPY_MAGIC_RE = None
        # Socket
        SURICATA_SOCKET_PATH = self.options.get("socket_file", None) 
        SURICATA_SOCKET_PYLIB = self.options.get("pylib_dir", None)

        # Command Line
        SURICATA_BIN = self.options.get("bin", None)

        suricata = {}
        suricata["alerts"]=[]
        suricata["tls"]=[]
        suricata["perf"]=[]
        suricata["files"]=[]
        suricata["http"]=[]
        suricata["dns"]=[]
        suricata["ssh"]=[]
        suricata["file_info"]=[]

        suricata["eve_log_full_path"] = None
        suricata["alert_log_full_path"] = None
        suricata["tls_log_full_path"] = None
        suricata["http_log_full_path"] = None
        suricata["file_log_full_path"] = None
        suricata["ssh_log_full_path"] = None
        suricata["dns_log_full_path"] = None

        SURICATA_ALERT_FULL_PATH = "%s/%s" % (self.logs_path, SURICATA_ALERT_LOG)
        SURICATA_TLS_LOG_FULL_PATH = "%s/%s" % (self.logs_path, SURICATA_TLS_LOG)
        SURICATA_HTTP_LOG_FULL_PATH = "%s/%s" % (self.logs_path, SURICATA_HTTP_LOG)
        SURICATA_SSH_LOG_FULL_PATH = "%s/%s" % (self.logs_path, SURICATA_SSH_LOG)
        SURICATA_DNS_LOG_FULL_PATH = "%s/%s" % (self.logs_path, SURICATA_DNS_LOG)
        SURICATA_EVE_LOG_FULL_PATH = "%s/%s" % (self.logs_path, SURICATA_EVE_LOG)
        SURICATA_FILE_LOG_FULL_PATH = "%s/%s" % (self.logs_path, SURICATA_FILE_LOG)
        SURICATA_FILES_DIR_FULL_PATH = "%s/%s" % (self.logs_path, SURICATA_FILES_DIR)

        if not os.path.exists(SURICATA_CONF):
            log.warning("Unable to Run Suricata: Conf File %s Does Not Exist" % (SURICATA_CONF))
            return suricata["alerts"]
        if not os.path.exists(self.pcap_path):
            log.warning("Unable to Run Suricata: Pcap file %s Does Not Exist" % (self.pcap_path))
            return suricata["alerts"]

        # Add to this if you wish to ignore any SIDs for the suricata alert logs
        # Useful for ignoring SIDs without disabling them. Ex: surpress an alert for
        # a SID which is a dependent of another. (Bad TCP data for HTTP(S) alert)
        sid_blacklist = [
                        # SURICATA FRAG IPv6 Fragmentation overlap
                        2200074,
                        # ET INFO InetSim Response from External Source Possible SinkHole
                        2017363,
                        # SURICATA UDPv4 invalid checksum
                        2200075,
                        # ET POLICY SSLv3 outbound connection from client vulnerable to POODLE attack
                        2019416,
        ]

        if SURICATA_RUNMODE == "socket":
            if SURICATA_SOCKET_PYLIB != None:
                sys.path.append(SURICATA_SOCKET_PYLIB)
            try:
                from suricatasc import SuricataSC
            except Exception as e:
                log.warning("Failed to import suricatasc lib %s" % (e))
                return suricata

            loopcnt = 0
            maxloops = 24
            loopsleep = 5

            args = {}
            args["filename"] = self.pcap_path
            args["output-dir"] = self.logs_path

            suris = SuricataSC(SURICATA_SOCKET_PATH)
            try:
                suris.connect()
                suris.send_command("pcap-file",args)
            except Exception as e:
                log.warning("Failed to connect to socket and send command %s: %s" % (SURICATA_SOCKET_PATH, e))
                return suricata
            while loopcnt < maxloops:
                try:
                    pcap_flist = suris.send_command("pcap-file-list")
                    current_pcap = suris.send_command("pcap-current")
                    log.debug("pcapfile list: %s current pcap: %s" % (pcap_flist, current_pcap))

                    if self.pcap_path not in pcap_flist["message"]["files"] and current_pcap["message"] != self.pcap_path:
                        log.debug("Pcap not in list and not current pcap lets assume it's processed")
                        break
                    else:
                        loopcnt = loopcnt + 1
                        time.sleep(loopsleep)
                except Exception as e:
                    log.warning("Failed to get pcap status breaking out of loop %s" % (e))
                    break

            if loopcnt == maxloops:
                log.warning("Loop timeout of %ssec occured waiting for file %s to finish processing" % (maxloops * loopsleep, pcapfile))
                return suricata
        elif SURICATA_RUNMODE == "cli":
            if not os.path.exists(SURICATA_BIN):
                log.warning("Unable to Run Suricata: Bin File %s Does Not Exist" % (SURICATA_CONF))
                return suricata["alerts"]
            cmd = "%s -c %s -k none -l %s -r %s" % (SURICATA_BIN,SURICATA_CONF,self.logs_path,self.pcap_path)
            ret,stdout,stderr = self.cmd_wrapper(cmd)
            if ret != 0:
               log.warning("Suricata returned a Exit Value Other than Zero %s" % (stderr))
               return suricata

        else:
            log.warning("Unknown Suricata Runmode")
            return suricata

        datalist = []
        if os.path.exists(SURICATA_EVE_LOG_FULL_PATH):
            suricata["eve_log_full_path"] = SURICATA_EVE_LOG_FULL_PATH
            with open(SURICATA_EVE_LOG_FULL_PATH, "r") as eve_log:
                datalist.append(eve_log.read())
        else:
            paths = [
                ("alert_log_full_path", SURICATA_ALERT_LOG_FULL_PATH),
                ("tls_log_full_path", SURICATA_TLS_LOG_FULL_PATH),
                ("http_log_full_path", SURICATA_HTTP_LOG_FULL_PATH),
                ("ssh_log_full_path", SURICATA_SSH_LOG_FULL_PATH),
                ("dns_log_full_path", SURICATA_DNS_LOG_FULL_PATH)
            ]
            for path in paths:
                if os.path.exists(path[1]):
                    suricata[path[0]] = path[1]
                    with open(path, "r") as the_log:
                        datalist.append(the_log.read())

        for data in datalist:
            for line in data.splitlines():
                try:
                    parsed = json.loads(line)
                except:
                    log.warning("Suricata: Failed to parse line as json" % (line))
                    continue

                if parsed["event_type"] == "alert":
                    if (parsed["alert"]["signature_id"] not in sid_blacklist
                        and not parsed["alert"]["signature"].startswith(
                            "SURICATA STREAM")):
                        alog = dict()
                        if parsed["alert"]["gid"] == '':
                            alog["gid"] = "None"
                        else:
                            alog["gid"] = parsed["alert"]["gid"]
                        if parsed["alert"]["rev"] == '':
                            alog["rev"] = "None"
                        else:
                            alog["rev"] = parsed["alert"]["rev"]
                        if parsed["alert"]["severity"] == '':
                            alog["severity"] = "None"
                        else:
                            alog["severity"] = parsed["alert"]["severity"]
                        alog["sid"] = parsed["alert"]["signature_id"]
                        alog["srcport"] = parsed["src_port"]
                        alog["srcip"] = parsed["src_ip"]
                        alog["dstport"] = parsed["dest_port"]
                        alog["dstip"] = parsed["dest_ip"]
                        alog["protocol"] = parsed["proto"]
                        alog["timestamp"] = parsed["timestamp"].replace("T", " ")
                        if parsed["alert"]["category"] == '':
                            alog["category"] = "None"
                        else:
                            alog["category"] = parsed["alert"]["category"]
                        alog["signature"] = parsed["alert"]["signature"]
                        suricata["alerts"].append(alog)

                elif parsed["event_type"] == "http":
                    hlog = dict()
                    hlog["srcport"] = parsed["src_port"]
                    hlog["srcip"] = parsed["src_ip"]
                    hlog["dstport"] = parsed["dest_port"]
                    hlog["dstip"] = parsed["dest_ip"]
                    hlog["timestamp"] = parsed["timestamp"].replace("T", " ")
                    try:
                        hlog["url"] = parsed["http"]["url"]
                    except:
                        hlog["url"] = "None"
                    hlog["length"] = parsed["http"]["length"]
                    try:
                        hlog["hostname"] = parsed["http"]["hostname"]
                    except:
                        hlog["hostname"] = "None"
                    try:
                        hlog["status"] = str(parsed["http"]["status"])
                    except:
                        hlog["status"] = "None"
                    hlog["method"] = parsed["http"]["http_method"]
                    try:
                       hlog["contenttype"] = parsed["http"]["http_content_type"]
                    except:
                        hlog["contenttype"] = "None"
                    try:
                        hlog["ua"] = parsed["http"]["http_user_agent"]
                    except:
                        hlog["ua"] = "None"
                    try:
                        hlog["referrer"] = parsed["http"]["http_refer"]
                    except:
                        hlog["referrer"] = "None"
                    suricata["http"].append(hlog)

                elif parsed["event_type"] == "tls":
                    tlog = dict()
                    tlog["srcport"] = parsed["src_port"]
                    tlog["srcip"] = parsed["src_ip"]
                    tlog["dstport"] = parsed["dest_port"]
                    tlog["dstip"] = parsed["dest_ip"]
                    tlog["timestamp"] = parsed["timestamp"].replace("T", " ")
                    tlog["fingerprint"] = parsed["tls"]["fingerprint"]
                    tlog["issuer"] = parsed["tls"]["issuerdn"]
                    tlog["version"] = parsed["tls"]["version"]
                    tlog["subject"] = parsed["tls"]["subject"]
                    suricata["tls"].append(tlog)

                elif parsed["event_type"] == "ssh":
                    suricata["ssh"].append(parsed)
                elif parsed["event_type"] == "dns":
                    suricata["dns"].append(parsed)

        else:
            log.warning("Suricata: Failed to find eve log at %s" % (SURICATA_EVE_LOG_FULL_PATH))

        if os.path.exists(SURICATA_FILE_LOG_FULL_PATH):
            suricata["file_log_full_path"] = SURICATA_FILE_LOG_FULL_PATH
            f = open(SURICATA_FILE_LOG_FULL_PATH).readlines()
            for l in f:
                try:
                    d = json.loads(l)
                except:
                    log.warning("failed to load JSON from file log")
                    continue
                # Some log entries do not have an id
                if "id" not in d:
                    continue
                src_file = "%s/file.%s" % (SURICATA_FILES_DIR_FULL_PATH,d["id"])
                if os.path.exists(src_file):
                    if SURICATA_FILE_COPY_MAGIC_RE and SURICATA_FILE_COPY_DST_DIR and os.path.exists(SURICATA_FILE_COPY_DST_DIR):
                        try:
                            m = re.search(SURICATA_FILE_COPY_MAGIC_RE,d["magic"])
                            if m:
                                dst_file = "%s/%s" % (SURICATA_FILE_COPY_DST_DIR,d["md5"])
                                shutil.copy2(src_file,dst_file)
                                log.warning("copied %s to %s" % (src_file,dst_file))
                        except Exception,e:
                            log.warning("Unable to copy suricata file: %s" % e)
                    file_info = File(file_path=src_file).get_all()
                    texttypes = [
                        "ASCII",
                        "Windows Registry text",
                        "XML document text",
                        "Unicode text",
                    ]
                    readit = False
                    for texttype in texttypes:
                        if texttype in file_info["type"]:
                            readit = True
                            break
                    if readit:
                        with open(file_info["path"], "r") as drop_open:
                            filedata = drop_open.read(SURICATA_FILE_BUFFER + 1)
                        if len(filedata) > SURICATA_FILE_BUFFER:
                            file_info["data"] = convert_to_printable(filedata[:SURICATA_FILE_BUFFER] + " <truncated>")
                        else:
                            file_info["data"] = convert_to_printable(filedata)
                    d["file_info"] = file_info
                if "/" in d["filename"]:
                    d["filename"] = d["filename"].split("/")[-1]
                suricata["files"].append(d)
        else:
            log.warning("Suricata: Failed to find file log at %s" % (SURICATA_FILE_LOG_FULL_PATH))

        if SURICATA_FILES_DIR_FULL_PATH and os.path.exists(SURICATA_FILES_DIR_FULL_PATH) and Z7_PATH and os.path.exists(Z7_PATH):
            # /usr/bin/7z a -pinfected -y files.zip files files-json.log
            cmd = "cd %s && %s a -p%s -y files.zip %s %s" % (self.logs_path,Z7_PATH,FILES_ZIP_PASS,SURICATA_FILE_LOG,SURICATA_FILES_DIR)
            ret,stdout,stderr = self.cmd_wrapper(cmd)
            if ret != 0:
                log.warning("Suricata: Failed to create %s/files.zip" % (self.logs_path))
        return suricata
