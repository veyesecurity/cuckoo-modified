# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.common.abstracts import Package

class JS(Package):
    """JavaScript analysis package."""
    PATHS = [
        ("SystemRoot", "system32", "wscript.exe"),
    ]

    def start(self, path):
        wscript = self.get_path("wscript.exe")
        args = "\"%s\"" % path
        ext = os.path.splitext(path)[-1].lower()
        if ext != ".js" and ext != ".jse":
            if os.path.isfile(path) and "#@~^" in open(path, "rb").read(100):
                os.rename(path,path + ".jse")
                path = path + ".jse"
            else:
                os.rename(path,path + ".js")
                path = path + ".js"
        args = "\"%s\"" % path
        return self.execute(wscript, args, path)
