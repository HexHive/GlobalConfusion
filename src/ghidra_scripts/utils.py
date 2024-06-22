from animator import Animator

################################################################################
# TYPING
################################################################################

from typing import Type, List
from ghidra.program.model.listing import Function
from ghidra.program.database import ProgramDB
from ghidra.program.database import ListingDB


from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.block import CodeBlockImpl
from ghidra.util.task import ConsoleTaskMonitor

from ghidra.program.model.pcode import (
    VarnodeAST,
    HighSymbol,
    PcodeOp,
    PcodeOpAST,
    HighOther,
    HighFunction,
    HighVariable,
    LocalSymbolMap,
    PcodeBlockBasic,
)


NON_GP_COMPLIANT = 0
GP_COMPLIANT= 1

################################################################################
# LOGGING
################################################################################

import logging

log = logging.getLogger(__name__)

################################################################################
# CODE
################################################################################


def dump_raw_pcode(program: ProgramDB, func: Function):
    animator = Animator()

    func_body = func.getBody()
    listing = program.getListing()
    opiter = listing.getInstructions(func_body, True)

    while opiter.hasNext():
        op = opiter.next()
        raw_pcode = op.getPcode()
        print("{}".format(op))
        for entry in raw_pcode:
            print("  {}".format(entry))


def _disasm_block(listing: ListingDB, bb: CodeBlockImpl):
    insn_iter = listing.getInstructions(bb, True)
    block_disasm = []
    while insn_iter.hasNext():
        ins = insn_iter.next()
        block_disasm.append(f"{ins.getAddressString(False, True)}:\t{ins}\l")
    return block_disasm


def cfg(program: ProgramDB, func: Function, disasm: bool = False) -> Type[Animator]:
    """Create an animator for the cfg of function `func`.

    Args:
        program (ProgramDB): the program context of `func`
        func (Function): the function to create the cfg for.
        disasm (bool, optional): include disassembly. Defaults to False.

    Returns:
        Type[Animator]: an animator to render the cfg of `func`
    """
    animator = Animator()
    blockModel = BasicBlockModel(program)
    monitor = ConsoleTaskMonitor()

    listing = program.getListing()
    body = func.getBody()
    first_addr = body.getMinAddress()
    last_addr = body.getMaxAddress()

    blocks = blockModel.getCodeBlocksContaining(body, monitor)

    while blocks.hasNext():
        bb = blocks.next()
        bb_name = hex(bb.getMinAddress().getOffset())
        animator.add_node(bb_name, label=bb_name)

        if disasm:
            insns = _disasm_block(listing, bb)
            insns_str = "".join(insns)
            label = f"{bb_name}:\n{insns_str}"
            animator.update_label(bb_name, label=label)

        dest = bb.getDestinations(monitor)
        while dest.hasNext():
            dbb = dest.next()
            dst_addr = dbb.getDestinationAddress()
            # destination blocks can be entrypoints of functions the current
            # function is calling. We exclude these destination blocks to create
            # an intra-procedural cfg. `getFunctionAt()` checks if the given
            # address is the start of a function.
            if getFunctionAt(dst_addr):
                continue

            if dst_addr < first_addr or dst_addr > last_addr:
                continue

            dbb_name = hex(dbb.getDestinationAddress().getOffset())
            animator.add_node(dbb_name, label=dbb_name)
            animator.add_edge(bb_name, dbb_name)
    return animator


################################################################################
# PRETTY-PRINTING GHIDRA OBJECTS
################################################################################


def get_raw_pcode(entity) -> List[PcodeOp]:
    """
    Get the raw pcode of the specified entity.

    Args:
        entity (PcodeOpAST | VarnodeAST): the entity to get the raw pcode of

    Returns:
        List[PcodeOp]: list of raw pcodes
    """
    instruction = None
    if isinstance(entity, PcodeOpAST):
        instruction: List[PcodeOp] = getInstructionAt(entity.getSeqnum().getTarget())
    elif isinstance(entity, VarnodeAST):
        instruction: List[PcodeOp] = getInstructionAt(entity.getPCAddress())

    if instruction:
        return instruction.getPcode()
    else:
        return []


def __str__VarnodeAST(self) -> str:
    """
    Monkey patch for prettier `__str__` of `VarnodeAST`.
    """

    out = "\n"
    instruction = getInstructionAt(self.getPCAddress())

    out += f"Varnode:\t{self}\n"
    out += f"type:\t{type(self)}\n"
    out += f"asm:\t{instruction}\n"

    out += f"raw pcode:\n"
    for raw_pcode in get_raw_pcode(self):
        out += f"\t{str(raw_pcode)}\n"

    out += f"refined pcode:\t{self.getDef()}\n"
    out += f"uniqueID:\t{self.getUniqueId()}\n"
    out += f"PCAddress:\t0x{self.getPCAddress()}\n"
    return out


def __str__PcodeOpAST(self) -> str:
    """
    Monkey patch for prettier `__str__` of `PcodeOpAST`.
    """

    out = "\n"
    out += f"PcodeOp:\t{self}\n"
    out += f"Address:\t{hex(self.getSeqnum().getTarget().getOffset())}\n"

    output: VarnodeAST = self.getOutput()
    if output:
        out += f"\nOutput: {output}, Address: 0x{output.getPCAddress()}, Pcode: {output.getDef()}\n"
        out += pp(output)
    for i, inp in enumerate(self.getInputs()):
        out += f"\nInput {i}: {inp}, Address: 0x{inp.getPCAddress()}, Pcode: {inp.getDef()}\n"
        out += pp(inp)
    return out


def pp(obj: object) -> str:
    if isinstance(obj, VarnodeAST):
        return __str__VarnodeAST(obj)
    elif isinstance(obj, PcodeOpAST):
        return __str__PcodeOpAST(obj)
    else:
        return f"{type(obj)} not supported"
