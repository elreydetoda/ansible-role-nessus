# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
    author: Alex (@RonJonArod)
    name: nessus_download
    short_description: returns the url for the requested nessus version
    description:
        - Takes the nessus version wanted and returns the url for the
    options:
      _terms:
        description:
          - nessus version wanted (specify latest for latest version)
        type: string
        required: true
      linux_distro:
        description:
          - the linux distro wanted for the download
        type: string
        required: true
      arch:
        description:
          - the architecture wanted for installation
        type: string
        required: true
"""

EXAMPLES = """
- name: Example of the change in the description
  ansible.builtin.debug:
    msg: "{{ lookup('community.general.cartesian', [1,2,3], [a, b])}}"

- name: loops over the cartesian product of the supplied lists
  ansible.builtin.debug:
    msg: "{{item}}"
  with_community.general.cartesian:
    - "{{list1}}"
    - "{{list2}}"
    - [1,2,3,4,5,6]
"""

RETURN = """
  _list:
    description:
      - list of lists composed of elements of the input lists
    type: list
    elements: list
"""

from typing import List, Dict, Union, Tuple
from re import search as r_search
from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

display = Display()

# I know there's a native way to do this...I didn't want to take the tiem to figure it out...
from requests import get as r_get, Response
from distutils.version import StrictVersion


class LookupModule(LookupBase):
    """
    Returns the url for the requested version of nessus
    """

    @property
    def _nessus_base_url(self) -> str:
        return "https://www.tenable.com/downloads/api/v2/pages/nessus"

    def _filter_filenames(
        self,
        possible_files: List[
            Dict[
                str,
                Union[str, int, bool],
            ],
        ],
        arch: str,
        distro: str,
    ) -> str:
        distro_mapping = {
            "amzn": {"amazon linux"},
            "amzn2": {"amazon linux 2"},
            "fbsd": {"freebsd"},
            "ubuntu": {},
            "debian": {"kali"},
            "msi": {"windows"},
            "suse": {"opensuse"},
            "fc": {"fedora"},
            "es": {"red hat", "rhel"},
            "dmg": {"osx", "mac", "macos", "apple"},
            "raspberrypios": {"rpi", "raspberry pi"},
        }

        expected_distro: str = None

        if distro in distro_mapping.keys():
            expected_distro = distro
        else:
            for distro_key, distro_set in distro_mapping.items():
                if distro in distro_set:
                    expected_distro = distro_key

        if expected_distro is None:
            raise AnsibleError(
                f"Unable to find {arch} in distro options: {distro_mapping.keys()}\n\nAlternative Options are: {distro_mapping.values()}"
            )

        download_obj: str = None

        if (expected_distro != "dmg") and arch in {
            "x86_64",
            "amd64",
            "aarch64",
            "i386",
            "Win32",
            "x64",
            "armhf",
        }:
            display.vvvvv(f"{possible_files}")
            for ness_file  in possible_files:
              display.vvvv(f"{arch}, {expected_distro}, {ness_file}")
              if arch in ness_file["file"] and expected_distro in ness_file["file"]:
                display.vvvv(f"reached: {ness_file}")
                download_obj = ness_file
                break

            if len(download_obj) > 1:
                AnsibleError("Please be more specific with the distro version")
            elif len(download_obj) == 0:
              AnsibleError("Too specific")

            display.vvvv(f"reached {download_obj}")

        elif expected_distro == "dmg":
            for ness_file in possible_files:
                if "dmg" in ness_file["file"]:
                    download_obj = ness_file

        if download_obj is not None:
            return {"checksum": download_obj["sha256"], "url": download_obj["file_url"]}

        raise AnsibleError("It's empyt")

        """
        various file names to match:
          Nessus-10.4.2-fc34.x86_64.rpm
          Nessus-10.4.2-suse12.x86_64.rpm
          Nessus-10.4.2-suse15.x86_64.rpm
          Nessus-10.4.2-ubuntu1404_amd64.deb
          Nessus-10.4.2-x64.msi
          Nessus-10.4.2-amzn.x86_64.rpm
          Nessus-10.4.2-amzn2.x86_64.rpm
          Nessus-10.4.2-fbsd12-amd64.txz
          Nessus-10.4.2-amzn2.aarch64.rpm
          Nessus-10.4.2-ubuntu1804_aarch64.deb
          Nessus-10.4.2-es9.aarch64.rpm
          Nessus-10.4.2-ubuntu1404_i386.deb
          Nessus-10.4.2-es6.x86_64.rpm
          Nessus-10.4.2-Win32.msi
          Nessus-10.4.2-es7.x86_64.rpm
          nessus-updates-10.4.2.tar.gz # not going to match on this at all
          Nessus-10.4.2.dmg
          Nessus-10.4.2-es8.x86_64.rpm
          Nessus-10.4.2-es8.aarch64.rpm
          Nessus-10.4.2-debian9_amd64.deb
          Nessus-10.4.2-raspberrypios_armhf.deb
          Nessus-10.4.2-es7.aarch64.rpm
          Nessus-10.4.2-es9.x86_64.rpm
          Nessus-10.4.2-debian9_i386.deb
        """

    @staticmethod
    def _nessus_ver(item: Tuple[str, dict]) -> str:
        sem_ver = r_search(r"(\d+\.\d+\.\d+)", item[0])
        display.vvvvv(f"Nessus version: {sem_ver}")
        return (sem_ver.group(), item[0], item[1])

    def _get_latest_version(self, json_data: dict) -> str:
        latest_json_data = json_data["latest"]
        display.vvvv("available versions are: %s", latest_json_data.keys())

        latest_version = sorted(latest_json_data.items(), key=self._nessus_ver)[0]
        display.vvvv(f"latest version: {latest_version[0]}")

        return latest_version

    def _get_version(
        self,
        version: str = "latest",
        arch: str = None,
        distro: str = None,
        possible_version: dict = None,
    ) -> str:

        if distro is None:
            raise AnsibleParserError()
        if possible_version is None:
            raise AnsibleError(
                "Unable to retrieve valid response from tenable website: %s",
                possible_version,
            )

        display.vvvvv("specified version %s", version)
        display.vvvvv("specified arch %s", arch)
        display.vvvvv("specified distro %s", distro)
        display.vvvvv("returned data from possible versions %s", possible_version)

        json_response = possible_version["releases"]

        if version == "latest":
            version_information = self._get_latest_version(json_response)[1]
        else:
            version_information = json_response[version]

        version_information: List[
            Dict[
                str,
                Union[bool, int, str],
            ]
        ]

        display.vvvvv(f"current version's information is: {version_information}")

        return self._filter_filenames(version_information, arch, distro)

    def run(self, terms, variables=None, **kwargs):

        # First of all populate options,
        # this will already take into account env vars and ini config
        self.set_options(var_options=variables, direct=kwargs)

        # lookups in general are expected to both take a list as input and output a list
        # this is done so they work with the looping construct 'with_'.
        ret = []
        for term in terms:
            display.debug("Nessus lookup term: %s" % term)

            try:
                if term:
                    display.vvvv("Lookup currently using: %s", term)
                    ret.append(
                        self._get_version(
                            term,
                            self.get_option("arch"),
                            self.get_option("linux_distro"),
                            r_get(self._nessus_base_url).json(),
                        ),
                    )
                else:
                    # Always use ansible error classes to throw 'final' exceptions,
                    # so the Ansible engine will know how to deal with them.
                    # The Parser error indicates invalid options passed
                    raise AnsibleParserError()
            except AnsibleParserError:
                raise AnsibleError("could not locate file in lookup: %s" % term)

        return ret
