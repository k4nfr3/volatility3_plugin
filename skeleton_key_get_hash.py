# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
from typing import Iterable, List, Tuple

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.plugins import yarascan
from volatility3.plugins.windows import pslist

from volatility3.framework.objects import utility


vollog = logging.getLogger(__name__)


class SkeletonKeyGetHash(interfaces.plugins.PluginInterface):
    """Scans all the Virtual Address Descriptor memory maps using yara."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel',
                                                     architectures = ["Intel32", "Intel64"]),
            requirements.URIRequirement(name = "yara_file", default= "volatility3/framework/plugins/windows/skeleton.yara", description = "Yara rules (as a file)", optional = True),
            # This additional requirement is to follow suit with upstream, who feel that compiled rules could potentially be used to execute malicious code
            # As such, there's a separate option to run compiled files, as happened with yara-3.9 and later
            requirements.PluginRequirement(name = 'pslist', plugin = pslist.PsList, version = (2, 0, 0)),
            requirements.VersionRequirement(name = 'yarascanner', component = yarascan.YaraScanner,
                                            version = (2, 0, 0))
        ]

    def _lsass_proc_filter(self, proc):
        """
        Used to filter to only lsass.exe processes

        There should only be one of these, but malware can/does make lsass.exe
        named processes to blend in or uses lsass.exe as a process hollowing target
        """
        process_name = utility.array_to_string(proc.ImageFileName)

        return process_name != "lsass.exe"


    def _generator(self):
        kernel = self.context.modules[self.config['kernel']]

        rules = yarascan.YaraScan.process_yara_options(dict(self.config))

        filter_func = self._lsass_proc_filter

        for task in pslist.PsList.list_processes(context = self.context,
                                                 layer_name = kernel.layer_name,
                                                 symbol_table = kernel.symbol_table_name,
                                                 filter_func = filter_func):
            layer_name = task.add_process_layer()
            layer = self.context.layers[layer_name]
            for offset, rule_name, name, value in layer.scan(context = self.context,
                                                             scanner = yarascan.YaraScanner(rules = rules),
                                                             sections = self.get_vad_maps(task)):
                vollog.debug("\nYara result Value = " + str(value) + "\n")
                shw = value.hex()
                shw = shw.upper()
                skeleton_hash = shw[16:24]+shw[32:40]+shw[48:56]+shw[64:72]
                clear_skeleton_key = ""
                if skeleton_hash=="60BA4FCADC466C7A033C178194C03DF6":
                    clear_skeleton_key="mimikatz"


                yield 0, (format_hints.Hex(offset), task.UniqueProcessId, "lsass.exe", skeleton_hash, clear_skeleton_key)
                #yield 0, (format_hints.Hex(offset), task.UniqueProcessId, rule_name, name, value)
        vollog.info("\n\nBruteForce the hash :")
        vollog.info("john --format=nt")
        vollog.info("hashcat -m 1000")


    @staticmethod
    def get_vad_maps(task: interfaces.objects.ObjectInterface) -> Iterable[Tuple[int, int]]:
        """Creates a map of start/end addresses within a virtual address
        descriptor tree.

        Args:
            task: The EPROCESS object of which to traverse the vad tree

        Returns:
            An iterable of tuples containing start and end addresses for each descriptor
        """
        vad_root = task.get_vad_root()
        for vad in vad_root.traverse():
            end = vad.get_end()
            start = vad.get_start()
            yield (start, end - start)

    def run(self):
        return renderers.TreeGrid([('Offset    ', format_hints.Hex), ('PID', int), ('Process    ', str), ('Skeleton_NTLM_Hash              ', str), ('Clear_Password', str)
                                   ], self._generator())
