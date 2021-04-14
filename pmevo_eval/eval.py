import logging
import pkg_resources
from typing import Sequence, TypeVar, List, Dict
from pathlib import Path
from functools import reduce
import re

from pmevo_eval.utils.architecture import Insn
from pmevo_eval.utils.mapping import Mapping
from pmevo_eval.processors.bottleneck_processor import BottleneckProcessor

logger = logging.getLogger(__name__)

_DATA_PATH = Path(pkg_resources.resource_filename("pmevo_eval", "data/"))

PALMED_INSTR_T = TypeVar("PALMED_INSTR_T")


class _OperandRe:
    """Applies a given regexp pattern and replaces it with a replacement string. This
    string can contain back-references, as well as numeric multiplications of the form
    `<EVAL:32x4>`."""

    def __init__(self, pattern: str, replacement: str):
        self.patstr = pattern
        self.pattern = re.compile(pattern)
        self.replacement = replacement

    def apply(self, val: str):
        out = self.pattern.sub(self.replacement, val)

        while True:
            next_eval = out.find("<EVAL:")
            if next_eval < 0:
                break
            eval_end = out.find(">", next_eval)
            eval_expr = out[next_eval + 6 : eval_end]
            numbers = map(int, eval_expr.strip().split("x"))
            value = reduce(lambda x, y: x * y, numbers)
            out = out[:next_eval] + str(value) + out[eval_end + 1 :]

        return out


class PmevoMapping:
    _pmevo_operands_re = [
        _OperandRe(r"\(\(REG:[A-Z]+:G:([0-9]+)\)\)", r"GPR\1"),
        _OperandRe(r"\(\(REG:[A-Z]+:V:([0-9]+)\)\)", r"VR\1"),
        _OperandRe(r"\(\(IMM:([0-9]+)\)\)", r"IMM\1"),
        _OperandRe(r"\(\(DIV:([0-9]+)\)\)", r"GPR\1"),
        _OperandRe(r"byte_ptr_\[[^\]]+\]", r"MEM8"),
        _OperandRe(r"dword_ptr_\[[^\]]+\]", r"MEM32"),
        _OperandRe(r"qword_ptr_\[[^\]]+\]", r"MEM64"),
        _OperandRe(r"xmmword_ptr_\[[^\]]+\]", r"MEM128"),
        _OperandRe(r"ymmword_ptr_\[[^\]]+\]", r"MEM256"),
        _OperandRe(r"\[[^\]]+\]", r"ADDR64"),
    ]

    _palmed_operands_re = [
        _OperandRe(r"MEM\d+\D+([0-9x]+)$", r"MEM<EVAL:\1>"),
        _OperandRe(r"GPR(\d+).*$", r"GPR\1"),
        _OperandRe(r"ADDR(\d+).*$", r"ADDR\1"),
        _OperandRe(r"VR(\d+).*$", r"VR\1"),
        _OperandRe(r"IMM\D+([0-9]+)$", r"IMM\1"),
    ]

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
                self.arch_name = arch_name
                self.mapping = Mapping.read_from_json_str(handle.read())
                self.processor = BottleneckProcessor(self.mapping)
        except FileNotFoundError as exn:
            raise self.ArchitectureNotFound(arch_name) from exn

        self._palmed_to_pmevo = None

    def cycles_for(self, insns: Sequence[Insn]):
        return self.processor.execute(list(insns))["cycles"]

    def ipc_for(self, insns: Sequence[Insn]):
        return len(insns) / self.cycles_for(insns)

    def map_instructions(
        self, palmed_iset: List[PALMED_INSTR_T]
    ) -> Dict[PALMED_INSTR_T, Insn]:
        """Generate a mapping from palmed instructions to a pmevo instruction set,
        based on a lot of guesswork"""

        if self._palmed_to_pmevo:
            return self._palmed_to_pmevo

        pmevo_iset = self.mapping.arch.insn_list()

        def canonicalize_with(mnemonic, ops_orig, regexps):
            ops = []
            for op in ops_orig:
                for op_re in regexps:
                    op = op_re.apply(op)
                ops.append(op)
            return (mnemonic, tuple(ops))

        def canonicalize_pmevo_instr(pmevo_instr: Insn):
            mnemonic_split = pmevo_instr.name.split("_", 1)
            try:
                mnemonic, ops_str = mnemonic_split
                ops_orig = list(map(lambda x: x.strip("_"), ops_str.strip().split(",")))
            except ValueError:
                mnemonic, ops_orig = mnemonic_split[0], []
            return canonicalize_with(mnemonic, ops_orig, self._pmevo_operands_re)

        def canonicalize_palmed_instr(palmed_instr: PALMED_INSTR_T):
            mnemonic_split = palmed_instr.name().split("_", 1)
            try:
                mnemonic, ops_str = mnemonic_split
                ops_orig = ops_str.split("_")
            except ValueError:
                mnemonic, ops_orig = mnemonic_split[0], []
            return canonicalize_with(mnemonic, ops_orig, self._palmed_operands_re)

        canonical_to_pmevo = {}
        for insn in pmevo_iset:
            canonical_to_pmevo[canonicalize_pmevo_instr(insn)] = insn

        insn_mapping = {}
        for insn in palmed_iset:
            canonical = canonicalize_palmed_instr(insn)
            if canonical not in canonical_to_pmevo:
                logger.debug("CANNOT MAP: %s <%s>", canonical, insn)
                insn_mapping[insn] = None
            else:
                insn_mapping[insn] = canonical_to_pmevo[canonical]

        logger.debug(
            "Unmapped: %d / %d.",
            len(list(filter(lambda x: insn_mapping[x] is None, insn_mapping.keys()))),
            len(pmevo_iset),
        )

        self._palmed_to_pmevo = insn_mapping
        return insn_mapping
