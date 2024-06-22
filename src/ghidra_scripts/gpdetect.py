from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.util import DisplayableEol
from ghidra.app.util import XReferenceUtil
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp, PcodeOpAST
from ghidra.program.model.address import GenericAddress
from ghidra.program.util import DefinedDataIterator

import sys
import os
import shutil
import re
import json
from pprint import pprint
import helpers

################################################################################
# TYPING
################################################################################

from typing import List, Dict, Set, Tuple, Hashable, Any

################################################################################
# LOGGING
################################################################################

import logging

log = logging.getLogger(__name__)

################################################################################
# GLOBALS
################################################################################

PROGRAM = getCurrentProgram()
GP_RETURN_CODES = {
    #    '0x0': 'SUCCESS',
    "ffff0000": "TEE_ERROR_GENERIC",
    "ffff0001": "TEE_ERROR_ACCESS_DENIED",
    "ffff0002": "TEE_ERROR_CANCEL",
    "ffff0003": "TEE_ERROR_ACCESS_CONFLICT",
    "ffff0004": "TEE_ERROR_EXCESS_DATA",
    "ffff0005": "TEE_ERROR_BAD_FORMAT",
    "ffff0006": "TEE_ERROR_BAD_PARAMETERS",
    "ffff0007": "TEE_ERROR_BAD_STATE",
    "ffff0008": "TEE_ERROR_ITEM_NOT_FOUND",
    "ffff0009": "TEE_ERROR_NOT_IMPLEMENTED",
    "ffff000a": "TEE_ERROR_NOT_SUPPORTED",
    "ffff000b": "TEE_ERROR_NO_DATA",
    "ffff000c": "TEE_ERROR_OUT_OF_MEMORY",
    "ffff000d": "TEE_ERROR_BUSY",
    "ffff000e": "TEE_ERROR_COMMUNICATION",
    "ffff000f": "TEE_ERROR_COMMUNICATION",
    "ffff0010": "TEE_ERROR_SHORT_BUFFER",
    "ffff0011": "TEE_ERROR_EXTERNAL_CANCEL",
    "ffff3001": "TEE_ERROR_TIMEOUT",
    "ffff300f": "TEE_ERROR_OVERFLOW",
    "ffff3024": "TEE_ERROR_TARGET_DEAD",
    "ffff3041": "TEE_ERROR_STORAGE_NO_SPACE",
    "ffff3071": "TEE_ERROR_MAC_INVALID",
    "ffff3072": "TEE_ERROR_SIGNATURE_INVALID",
    "ffff5000": "TEE_ERROR_TIME_NOT_SET",
}

################################################################################
# CODE
################################################################################

DECOMPILE_FUNCTION_CACHE = {}


def getAddress(offset):
    return (
        PROGRAM.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
    )


class FlowNode:
    def __init__(self, var_node):
        """Used to get VarNode value

        :param var_node:
        """
        self.var_node = var_node

    def get_value(self):
        """Get VarNode value depend on it's type.

        :return:
        """
        if self.var_node.isAddress():
            log.debug("Var_node isAddress")
            # TODO: Return pointer value is address is pointer, this might cause some bug, need more test.
            # try:
            #     if getDataAt(self.var_node.getAddress()).isPointer():
            #         self.logger.info("Var_node address is pointer")
            #         return getDataAt(self.var_node.getAddress()).getValue().getOffset()
            #
            # except BaseException as err:
            #     self.logger.err(err)
            #     return self.var_node.getAddress()
            #
            return self.var_node.getAddress()
        elif self.var_node.isConstant():
            log.debug("Var_node isConstant")
            return self.var_node.getAddress()
        elif self.var_node.isUnique():
            log.debug("Var_node isUnique")
            return calc_pcode_op(self.var_node.getDef())
        elif self.var_node.isRegister():
            log.debug("Var_node isRegister")
            log.debug(self.var_node.getDef())
            return calc_pcode_op(self.var_node.getDef())
        elif self.var_node.isPersistant():
            log.debug("Var_node isPersistant")
            # TODO: Handler this later
            return
        elif self.var_node.isAddrTied():
            log.debug("Var_node isAddrTied")
            return calc_pcode_op(self.var_node.getDef())
        elif self.var_node.isUnaffected():
            log.debug("Var_node isUnaffected")
            # TODO: Handler this later
            return
        else:
            log.debug("self.var_node: {}".format(self.var_node))


def calc_pcode_op(pcode):
    log.debug("pcode: {}, type: {}".format(pcode, type(pcode)))
    if isinstance(pcode, PcodeOpAST):
        opcode = pcode.getOpcode()
        if opcode == PcodeOp.PTRSUB:
            log.debug("PTRSUB")
            var_node_1 = FlowNode(pcode.getInput(0))
            var_node_2 = FlowNode(pcode.getInput(1))
            value_1 = var_node_1.get_value()
            value_2 = var_node_2.get_value()
            if isinstance(value_1, GenericAddress) and isinstance(
                value_2, GenericAddress
            ):
                return value_1.getOffset() + value_2.getOffset()

            else:
                log.debug("value_1: {}".format(value_1))
                log.debug("value_2: {}".format(value_2))
                return None

        elif opcode == PcodeOp.CAST:
            log.debug("CAST")
            var_node_1 = FlowNode(pcode.getInput(0))
            value_1 = var_node_1.get_value()
            if isinstance(value_1, GenericAddress):
                return value_1.getOffset()

            else:
                return None

        elif opcode == PcodeOp.PTRADD:
            log.debug("PTRADD")
            var_node_0 = FlowNode(pcode.getInput(0))
            var_node_1 = FlowNode(pcode.getInput(1))
            var_node_2 = FlowNode(pcode.getInput(2))
            try:
                value_0_point = var_node_0.get_value()
                log.debug("value_0_point: {}".format(value_0_point))
                if not isinstance(value_0_point, GenericAddress):
                    return
                value_0 = toAddr(getInt(value_0_point))
                log.debug("value_0: {}".format(value_0))
                log.debug("type(value_0): {}".format(type(value_0)))
                value_1 = var_node_1.get_value()
                log.debug("value_1: {}".format(value_1))
                log.debug("type(value_1): {}".format(type(value_1)))
                if not isinstance(value_1, GenericAddress):
                    log.debug("value_1 is not GenericAddress!")
                    return
                value_1 = get_signed_value(value_1.getOffset())
                # TODO: Handle input2 later
                value_2 = var_node_2.get_value()
                log.debug("value_2: {}".format(value_2))
                log.debug("type(value_2): {}".format(type(value_2)))
                if not isinstance(value_2, GenericAddress):
                    return
                output_value = value_0.add(value_1)
                log.debug("output_value: {}".format(output_value))
                return output_value.getOffset()

            except Exception as err:
                log.debug(
                    "Got something wrong with calc PcodeOp.PTRADD : {}".format(
                        err
                    )
                )
                return None

            except:
                log.error("Got something wrong with calc PcodeOp.PTRADD ")
                return None

        elif opcode == PcodeOp.INDIRECT:
            log.debug("INDIRECT")
            # TODO: Need find a way to handle INDIRECT operator.
            return None

        elif opcode == PcodeOp.MULTIEQUAL:
            log.debug("MULTIEQUAL")
            # TODO: Add later
            return None

        elif opcode == PcodeOp.COPY:
            log.debug("COPY")
            log.debug("input_0: {}".format(pcode.getInput(0)))
            log.debug("Output: {}".format(pcode.getOutput()))
            var_node_0 = FlowNode(pcode.getInput(0))
            value_0 = var_node_0.get_value()
            return value_0

    else:
        log.debug("Found Unhandled opcode: {}".format(pcode))
        return None


class FunctionAnalyzer(object):
    def __init__(self, function, timeout=30, logger=log):
        """

        :param function: Ghidra function object.
        :param timeout: timeout for decompile.
        :param logger: logger.
        """
        self.function = function
        self.timeout = timeout
        if logger is None:
            log = get_logger("FunctionAnalyzer")
        else:
            log = logger
        self.hfunction = None
        self.call_pcodes = {}
        self.prepare()

    def prepare(self):
        self.hfunction = self.get_hfunction()
        self.get_all_call_pcode()

    def get_hfunction(self):
        decomplib = DecompInterface()
        decomplib.openProgram(PROGRAM)
        timeout = self.timeout
        dRes = decomplib.decompileFunction(self.function, timeout, getMonitor())
        hfunction = dRes.getHighFunction()
        return hfunction

    def get_function_pcode(self):
        if self.hfunction:
            try:
                ops = self.hfunction.getPcodeOps()

            except:
                return None

            return ops

    def print_pcodes(self):
        ops = self.get_function_pcode()
        while ops.hasNext():
            pcodeOpAST = ops.next()
            print(pcodeOpAST)
            opcode = pcodeOpAST.getOpcode()
            print("Opcode: {}".format(opcode))
            if opcode == PcodeOp.CALL:
                print(
                    "We found Call at 0x{}".format(
                        pcodeOpAST.getInput(0).getPCAddress()
                    )
                )
                call_addr = pcodeOpAST.getInput(0).getAddress()
                print(
                    "Calling {}(0x{}) ".format(
                        getFunctionAt(call_addr), call_addr
                    )
                )
                inputs = pcodeOpAST.getInputs()
                for i in range(len(inputs)):
                    parm = inputs[i]
                    print("parm{}: {}".format(i, parm))

    def find_perv_call_address(self, address):
        try:
            address_index = sorted(self.call_pcodes.keys()).index(address)

        except Exception as err:
            return

        if address_index > 0:
            perv_address = sorted(self.call_pcodes.keys())[address_index - 1]
            return self.call_pcodes[perv_address]

    def find_next_call_address(self, address):
        try:
            address_index = sorted(self.call_pcodes.keys()).index(address)

        except Exception as err:
            return

        if address_index < len(self.call_pcodes) - 1:
            next_address = sorted(self.call_pcodes.keys())[address_index + 1]
            return self.call_pcodes[next_address]

    def get_all_call_pcode(self):
        ops = self.get_function_pcode()
        if not ops:
            return

        while ops.hasNext():
            pcodeOpAST = ops.next()
            opcode = pcodeOpAST.getOpcode()
            if opcode in [PcodeOp.CALL, PcodeOp.CALLIND]:
                op_call_addr = pcodeOpAST.getInput(0).getPCAddress()
                self.call_pcodes[op_call_addr] = pcodeOpAST

    def get_call_pcode(self, call_address):
        # TODO: Check call_address is in function.
        if call_address in self.call_pcodes:
            return self.call_pcodes[call_address]

        return

    def analyze_call_parms(self, call_address):
        parms = {}
        # TODO: Check call_address is in function.
        pcodeOpAST = self.get_call_pcode(call_address)
        if pcodeOpAST:
            log.debug(
                "We found target call at 0x{} in function {}(0x{})".format(
                    pcodeOpAST.getInput(0).getPCAddress(),
                    self.function.getName(),
                    hex(self.function.getEntryPoint().getOffset()),
                )
            )
            opcode = pcodeOpAST.getOpcode()
            if opcode == PcodeOp.CALL:
                target_call_addr = pcodeOpAST.getInput(0).getAddress()
                log.debug("target_call_addr: {}".format(target_call_addr))

            elif opcode == PcodeOp.CALLIND:
                target_call_addr = FlowNode(pcodeOpAST.getInput(0)).get_value()
                log.debug("target_call_addr: {}".format(target_call_addr))

            inputs = pcodeOpAST.getInputs()
            for i in range(len(inputs))[1:]:
                parm = inputs[i]
                log.debug("parm{}: {}".format(i, parm))
                parm_node = FlowNode(parm)
                log.debug("parm_node: {}".format(parm_node))
                parm_value = parm_node.get_value()
                log.debug("parm_value: {}".format(parm_value))
                if isinstance(parm_value, GenericAddress):
                    parm_value = parm_value.getOffset()
                parms[i] = parm_value
                if parm_value:
                    log.debug("parm{} value: {}".format(i, hex(parm_value)))
            return parms
        return

    def get_inputs(self, call_address):
        parms = []
        pcodeOpAST = self.get_call_pcode(call_address)
        if pcodeOpAST:
            log.debug(
                "We found target call at 0x{} in function {}(0x{})".format(
                    pcodeOpAST.getInput(0).getPCAddress(),
                    self.function.getName(),
                    hex(self.function.getEntryPoint().getOffset()),
                )
            )
            opcode = pcodeOpAST.getOpcode()
            if opcode == PcodeOp.CALL:
                target_call_addr = pcodeOpAST.getInput(0).getAddress()
                log.debug("target_call_addr: {}".format(target_call_addr))

            elif opcode == PcodeOp.CALLIND:
                target_call_addr = FlowNode(pcodeOpAST.getInput(0)).get_value()
                log.debug("target_call_addr: {}".format(target_call_addr))

            inputs = pcodeOpAST.getInputs()
            for i in range(len(inputs))[1:]:
                parms.append(inputs[i])
        return parms

    def get_call_parm_value(self, call_address):
        parms_value = {}
        if not call_address in self.call_pcodes:
            return
        parms = self.analyze_call_parms(call_address)

        if not parms:
            return

        for i in parms:
            log.debug("parms{}: {}".format(i, parms[i]))
            parm_value = parms[i]
            log.debug("parm_value: {}".format(parm_value))
            parm_data = None
            if parm_value:
                if is_address_in_current_program(toAddr(parm_value)):
                    if getDataAt(toAddr(parm_value)):
                        parm_data = getDataAt(toAddr(parm_value))
                    elif getInstructionAt(toAddr(parm_value)):
                        parm_data = getFunctionAt(toAddr(parm_value))

            parms_value["parm_{}".format(i)] = {
                "parm_value": parm_value,
                "parm_data": parm_data,
            }

        return parms_value


def find_gp_return_codes_occurrences():
    """Returns a dictionary containing all found gp return codes and their functions.

    The structure of the dict looks like this:
        { "<return_code>": {"<func_addr>": ["<ret_code_addr>", ...], "<func_name>": [...],
          "<return_code>": ...
        }

    Example:
        {'0xFFFF0000': {11646L: ['0x308c'], 382134L: ['0x5d522']},
         '0xFFFF0001': {62194L: ['0xf472']},
         '0xFFFF0005': {353376L: ['0x564c0']},
         '0xFFFF0006': {11646L: ['0x2d86', '0x2dda'], ...
         }

        Returns:
            (:obj:`dict`): dict of return codes and functions.
    """

    fm = PROGRAM.getFunctionManager()
    listing = PROGRAM.getListing()
    occurrences = {key: {} for key in GP_RETURN_CODES.keys()}

    funcs = fm.getFunctions(True)  # True means 'forward'
    func = fm.getFunctionAt(getAddress(0x1175C))

    """
    for func in funcs:
        addrSet = func.getBody()
        codeUnits = listing.getCodeUnits(addrSet, True)  # true means 'forward'
        for codeUnit in codeUnits:
            # ghidra resolves values (e.g., 32-bit contants) in its auto comments
            deol = DisplayableEol(codeUnit, True, True, True, True, 5, True, True)
            if deol.hasAutomatic():
                insn_str = "{} // {}".format(
                    codeUnit, deol.getAutomaticComment()
                ).lower()
            else:
                insn_str = "{}".format(codeUnit).lower()

            for key in GP_RETURN_CODES.keys():
                if key in insn_str:
                    entry = func.getEntryPoint()
                    if entry not in occurrences[key]:
                        occurrences[key][entry] = []
                    occurrences[key][entry].append(codeUnit.getAddress())
    """
    return occurrences


def find_common_xrefs(f, functions):
    """Find all funcs in `funcs` that have a common xref with f."""

    fm = PROGRAM.getFunctionManager()
    listing = PROGRAM.getListing()

    xrefs = XReferenceUtil.getXRefList(listing.getCodeUnitAt(f))
    assert len(xrefs) == 1

    needle_xref = xrefs[0]
    needle_xref_func = fm.getFunctionContaining(needle_xref)

    # xref is not a func, we terminate
    if not needle_xref_func:
        return []

    out = []
    for func in functions:
        xrefs = XReferenceUtil.getXRefList(listing.getCodeUnitAt(func))
        assert len(xrefs) == 1
        hay_xref = xrefs[0]

        hay_xref_func = fm.getFunctionContaining(hay_xref)
        # log.info("{} vs {}\n".format(get_func(needle_xref.frm), get_func(hay_xref.frm)))
        if hay_xref_func and hay_xref_func == needle_xref_func:
            out.append(func)
    return out


def filter_common_xrefs(funcs):
    """Get lists of funcs having common xrefs.

    The result is a list of lists where each list contains Ghidra Addresses.
    Addresses in a list have the the same xref.
    """
    common_xrefs = {}
    for idx, func in enumerate(funcs):
        # copy funcs and delete idx we are working on
        funcs_copy = funcs[::]
        del funcs_copy[idx]
        common_xref_funcs = find_common_xrefs(func, funcs_copy)

        if common_xref_funcs:
            common_xrefs[func] = common_xref_funcs

    sets = list()
    for key in common_xrefs.keys():
        curr_set = set()
        curr_set.add(key)
        for item in common_xrefs[key]:
            curr_set.add(item)
        sets.append(curr_set)

    out_list = list()
    for set_ in set(frozenset(s) for s in sets):
        out_list.append(list(set_))

    return out_list


def is_params_match(invoke_cmd_addr, open_session_addr):
    """TODO

    Args:
        invoke_cmd_addr (:obj:`Address`): Ghidra Address of invoke command func entry
        open_session_addr (:obj:`Address`): Ghidra Address open session func entry

    Returns:
        (:obj:`TODO`):
    """
    parms_data = {}

    listing = PROGRAM.getListing()
    fm = PROGRAM.getFunctionManager()
    invoke_cmd_xref = XReferenceUtil.getXRefList(
        listing.getCodeUnitAt(invoke_cmd_addr)
    )[0]
    open_session_xref = XReferenceUtil.getXRefList(
        listing.getCodeUnitAt(open_session_addr)
    )[0]

    invoke_cmd_xref_func = fm.getFunctionContaining(invoke_cmd_xref)
    if not invoke_cmd_xref_func:
        return False
    target = FunctionAnalyzer(invoke_cmd_xref_func)
    DECOMPILE_FUNCTION_CACHE[invoke_cmd_addr] = target
    parms_data[invoke_cmd_xref] = {
        "call_addr": invoke_cmd_xref,
        "refrence_function_addr": invoke_cmd_xref_func.getEntryPoint(),
        "refrence_function_name": invoke_cmd_xref_func.getName(),
        "parms": {},
    }
    invoke_cmd_parms = target.get_inputs(call_address=invoke_cmd_xref)
    # log.info(invoke_cmd_parms)

    open_session_xref_func = fm.getFunctionContaining(open_session_xref)
    if not open_session_xref_func:
        return False
    target = FunctionAnalyzer(open_session_xref_func)
    DECOMPILE_FUNCTION_CACHE[open_session_addr] = target
    parms_data[open_session_xref] = {
        "call_addr": open_session_xref,
        "refrence_function_addr": open_session_xref_func.getEntryPoint(),
        "refrence_function_name": open_session_xref_func.getName(),
        "parms": {},
    }
    open_session_parms = target.get_inputs(call_address=open_session_xref)
    # log.info(open_session_parms)

    if len(invoke_cmd_parms) < 4 or len(open_session_parms) < 2:
        return False

    # TODO: dirty hack, Ghidra's varnode `equals` does not seem to work here, we should figure out why.
    if (
        invoke_cmd_parms[3].getOffset() == open_session_parms[1].getOffset()
        and invoke_cmd_parms[3].getSize() == open_session_parms[1].getSize()
        and invoke_cmd_parms[3].getSpace() == open_session_parms[1].getSpace()
    ):
        return True

    return False


def get_decompiled_func(func):
    """returns a string containing the C source of the Function func.

    Args:
        func (:obj:`Function`): Ghidra Function.

    Returns:
        (:obj:`str`): C source code string decompiled function or None, if decompilation fails
    """
    ifc = DecompInterface()
    ifc.openProgram(PROGRAM)
    results = ifc.decompileFunction(func, 0, ConsoleTaskMonitor())
    if results is None:
        return None
    decompiled_function = results.getDecompiledFunction()
    if decompiled_function is None:
        return None
    return decompiled_function.getC()


def find_candidates_for_kinibi():
    """Find gp api candidates using kinibi specific contants.

    A common structure for the lifecycle handler found in kinbi TAs is this one:
    if (iVar1 == 0xff01) {
        ...
    }
    else {
      if (iVar1 == 0xff02) {
          ...
          iVar1 = FUN_00007154(param_1[2],auStack52,&DAT_00093f50); // this is OpenSession
      }
      else {
        iVar1 = FUN_000071a6(DAT_00093f50,iVar1,param_1[2],auStack52); // this is InvokeCommand
      }

    We look for the constants 0xff01 and 0xff02, get the function they occur in, and return all functions
    called by this function as candidates.
    """
    lh_candidates = []
    fm = PROGRAM.getFunctionManager()
    funcs = fm.getFunctions(True)  # True means 'forward'
    for func in funcs:
        # log.debug("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
        source = get_decompiled_func(func)
        if source is None:
            continue
        m = re.search(r"(0xff01|0xff02)", source, re.DOTALL)
        if m:
            lh_candidates.append(func)

    gp_candidates = []
    for lh_candidate in lh_candidates:
        for gp_candidate in lh_candidate.getCalledFunctions(
            ConsoleTaskMonitor()
        ):
            gp_candidates.append(gp_candidate.getEntryPoint())
    return gp_candidates


def find_candidates_for_qsee():
    ic_sdk_func = []
    oc_sdk_func = []
    fm = PROGRAM.getFunctionManager()
    funcs = fm.getFunctions(True)  # True means 'forward'
    for func in funcs:
        log.debug(
            "Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint())
        )
        source = get_decompiled_func(func)
        if source is None:
            continue
        icm = re.search(r".*?0xfffe.*?0x55.*?0xc.*?.0xb*?", source, re.DOTALL)
        if icm:
            ic_sdk_func.append(func)

        ocm = re.search(
            r".*?0xfffd.*?0x1156.*?0x1266d.*?0xffff000c.*?", source, re.DOTALL
        )
        if ocm:
            oc_sdk_func.append(func)

    ic_candidates = []
    oc_candidates = []
    for ic_candidate in ic_sdk_func:
        for gp_candidate in ic_candidate.getCalledFunctions(
            ConsoleTaskMonitor()
        ):
            ic_candidates.append(gp_candidate.getEntryPoint())

    for oc_candidate in oc_sdk_func:
        for gp_candidate in oc_candidate.getCalledFunctions(
            ConsoleTaskMonitor()
        ):
            oc_candidates.append(gp_candidate.getEntryPoint())
    return ic_candidates, oc_candidates


def detect() -> Tuple[int, int]:
    listing = PROGRAM.getListing()
    fm = PROGRAM.getFunctionManager()

    # we collect a list of Ghidra Address objects to our GP API candidates
    funcs = []

    # get gp candidate functions by looking for gp specific return codes
    # TODO: the approach to obtain constants from comments does not work very well,
    # try to create backward slices from RETURN pcode insns and collect constants this way
    # gp_codes = find_gp_return_codes_occurrences()

    # we just need the functions, so get a list of unique function names
    # funcs.extend(
    #     list(
    #         set([func_addr for item in gp_codes.values() for func_addr in item.keys()])
    #     )
    # )

    # get more candidates based on vendor-specific heuristics
    # funcs.extend(find_candidates_for_kinibi())
    ic_candidates, oc_candidates = find_candidates_for_qsee()

    # make sure we have no duplicates for further steps
    # funcs = list(set(funcs))

    # pprint([hex(f.getUnsignedOffset()) for f in funcs])

    invoke_command_func = None
    open_session_func = None

    if ic_candidates:
        ic_real_candidates = []
        for func in ic_candidates:
            if fm.getFunctionContaining(func).getParameterCount() == 4:
                ic_real_candidates.append(func)

        if len(ic_real_candidates) == 1:
            invoke_command_func = getFunctionAt(ic_real_candidates[0])

    if oc_candidates:
        oc_real_candidates = []
        for func in oc_candidates:
            if fm.getFunctionContaining(func).getParameterCount() == 3:
                oc_real_candidates.append(func)

        if len(oc_real_candidates) == 1:
            open_session_func = getFunctionAt(oc_real_candidates[0])

    return open_session_func, invoke_command_func


def detect_dumb():
    program = getCurrentProgram()
    monitor = ConsoleTaskMonitor()
    memory = program.getMemory()
    binaryPath = program.getExecutablePath()
    listing = program.getListing()
    filename = os.path.basename(binaryPath)
    decompinterface = DecompInterface()
    decompinterface.openProgram(program)
    functionManager = program.getFunctionManager()
    functions = functionManager.getFunctions(True)
    addressFactory = program.getAddressFactory()
    print(
        8 * "*"
        + "ta_invokeCommandEntryPoint(QSEE DUMB) finder analyzing: "
        + filename
        + 8 * "="
    )
    # look for TA_InvokeCommandEntryPoint
    TA_Invoke_Candidates = []
    for f in functions:
        if f.getName() == "MultibuildInternal_TA_InvokeCommandEntryPoint":
            TA_Invoke_Candidates.append(f)
            break
    if len(TA_Invoke_Candidates) > 0:
        return TA_Invoke_Candidates
    multiple_refs = []
    for string in DefinedDataIterator.definedStrings(program):
        for ref in XReferenceUtil.getXRefList(string):
            if "TA_InvokeCommandEntryPoint" in string.toString():
                print("found TA_InvokeCommandEntryPoint string", string, ref)
                user_ta_entry_function_cand = (
                    functionManager.getFunctionContaining(ref)
                )
                if user_ta_entry_function_cand is None:
                    continue
                if user_ta_entry_function_cand.getName() in multiple_refs:
                    continue
                if user_ta_entry_function_cand.getParameterCount() == 4:
                    TA_Invoke_Candidates.append(user_ta_entry_function_cand)
                    multiple_refs.append(user_ta_entry_function_cand.getName())

    return TA_Invoke_Candidates


def detect_less_dumb():
    program = getCurrentProgram()
    monitor = ConsoleTaskMonitor()
    memory = program.getMemory()
    binaryPath = program.getExecutablePath()
    listing = program.getListing()
    filename = os.path.basename(binaryPath)
    decompinterface = DecompInterface()
    decompinterface.openProgram(program)
    functionManager = program.getFunctionManager()
    functions = functionManager.getFunctions(True)
    addressFactory = program.getAddressFactory()
    log.info(
        8 * "*"
        + "ta_invokeCommandEntryPoint(QSEE less DUMB) finder analyzing: "
        + filename
        + 8 * "="
    )

    # first, try to look for the `MultibuildInternal_TA_CreateEntryPoint`
    # function
    TA_Invoke_Candidates = []
    for f in functions:
        if f.getName() == "MultibuildInternal_TA_InvokeCommandEntryPoint":
            TA_Invoke_Candidates.append(f)
            print("MultibuildInternal_TA_InvokeCommandEntryPoint found!!!")
            return TA_Invoke_Candidates, helpers.GP_COMPLIANT

    # second, try to look for references to an `TA_InvokeCommandEntryPoint`
    # string
    TA_Invoke_Candidates = []
    multiple_refs = []
    for string in DefinedDataIterator.definedStrings(program):
        for ref in XReferenceUtil.getXRefList(string):
            if "TA_InvokeCommandEntryPoint" in string.toString():
                print("found TA_InvokeCommandEntryPoint string", string, ref)
                user_ta_entry_function_cand = (
                    functionManager.getFunctionContaining(ref)
                )
                if user_ta_entry_function_cand is None:
                    print("user_ta_entry_function_cand is None")
                    continue
                if user_ta_entry_function_cand.getName() in multiple_refs:
                    print("????", multiple_refs)
                    continue
                tmp_decomp_results = decompinterface.decompileFunction(
                    user_ta_entry_function_cand, 30, monitor
                )
                tmp_sig = (
                    tmp_decomp_results.getDecompiledFunction().getSignature()
                )
                print(tmp_sig)
                if "param_4" in tmp_sig and not "param_5" in tmp_sig:
                    # this cursed shit works bettern then getparameterCount for some @#! reason...
                    TA_Invoke_Candidates.append(user_ta_entry_function_cand)
                    multiple_refs.append(user_ta_entry_function_cand.getName())
                else:
                    print(
                        "wtf?", user_ta_entry_function_cand.getParameterCount()
                    )
    if len(TA_Invoke_Candidates) > 0:
        return TA_Invoke_Candidates, helpers.GP_COMPLIANT
    fromMinkFunc = None
    for string in DefinedDataIterator.definedStrings(program):
        for ref in XReferenceUtil.getXRefList(string):
            if "GPParams_newFromMinkInternal" in string.toString():
                print(
                    "found GPParams_newFromMinkInternal string",
                    string,
                    ref,
                    filename,
                )
                fromMinkFunc = functionManager.getFunctionContaining(ref)
                break
    if fromMinkFunc is None:
        print("fromMinkFunc is None : ", filename)
        return [], helpers.NON_GP_COMPLIANT
    TA_Invoke_Candidates = []
    for calling_f in fromMinkFunc.getCallingFunctions(monitor):
        for pot_invoke_cmd in calling_f.getCalledFunctions(monitor):
            if pot_invoke_cmd.getParameterCount() == 4:
                TA_Invoke_Candidates.append(pot_invoke_cmd)
    if len(TA_Invoke_Candidates) == 0:
        print(
            "no potential candiate found :()",
            len(fromMinkFunc.getCallingFunctions(monitor)),
            filename,
        )
        return [], helpers.NON_GP_COMPLIANT
    return TA_Invoke_Candidates, helpers.GP_COMPLIANT
