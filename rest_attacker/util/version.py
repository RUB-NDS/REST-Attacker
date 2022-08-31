# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Retrieves the version number.
"""

import subprocess
import sys
from argparse import Action


class GetVersion(Action):
    """
    Retrieves version number using 'git describe'.
    """

    def __call__(self, parser, namespace, values, option_string=None):
        version = subprocess.check_output(
            ["git", "describe", "--always"]).strip()
        print(version.decode("utf8"))

        sys.exit(0)
