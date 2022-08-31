# Copyright (C) 2021-2022 the REST-Attacker authors. See COPYING and CONTRIBUTORS.md for legal info.

"""
Implementation of report objects.
"""

import json


class Report:
    """
    Report of an individual check.
    """

    def __init__(self, check_id: int, content: dict = None) -> None:
        """
        Create a new report.

        :param check_id: Identifier of the check that the report is generated for.
        :type check_id: int
        :param content: Content (= parameters and values) of the report.
        :type content: dict
        """
        self.report_id = check_id
        self.content = {}

        if content:
            self.content.update(content)

    def dump(self) -> dict:
        """
        Create a dict with the report contents.
        """
        output = {
            "report_id": self.report_id
        }
        output.update(self.content)

        return output

    def dumps(self, outformat: str = "json") -> str:
        """
        Create a string representation of the report.

        :param format: Data representation format of the report.
        :type format: str
        """
        if outformat == "json":
            output = json.dumps(self.content, sort_keys=True, indent=4)

            return output

        else:
            raise ValueError(
                f"Format '{outformat}' unknown: Cannot be used to generate reports.")
