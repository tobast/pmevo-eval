import pkg_resources
from typing import Sequence
from pathlib import Path

from pmevo_eval.utils.architecture import Insn
from pmevo_eval.utils.mapping import Mapping
from pmevo_eval.processors.bottleneck_processor import BottleneckProcessor

_DATA_PATH = Path(pkg_resources.resource_filename("pmevo_eval", "data/"))


class PmevoMapping:
    class ArchitectureNotFound(Exception):
        pass

    def __init__(self, arch_name):
        """ Setup PMEvo for a given architecture, or raise ArchitectureNotFound """
        assert "/" not in arch_name and ".." not in arch_name
        mapping_path = _DATA_PATH / arch_name / "mapping_pmevo.json"
        if not mapping_path.is_file():
            raise self.ArchitectureNotFound(arch_name)

        try:
            with mapping_path.open("r") as handle:
                self.mapping = Mapping.read_from_json_str(handle.read())
                self.processor = BottleneckProcessor(self.mapping)
        except FileNotFoundError as exn:
            raise self.ArchitectureNotFound(arch_name) from exn

    def cycles_for(self, insns: Sequence[Insn]):
        return self.processor.execute(list(insns))["cycles"]

    def ipc_for(self, insns: Sequence[Insn]):
        return len(insns) / self.cycles_for(insns)
