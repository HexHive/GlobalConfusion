import re
import os
import helpers

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.util import DefinedDataIterator
from ghidra.app.util import XReferenceUtil

# from ghidra.program.model.listing import getCalledFunctions, getCallingFunctions


def find_mitee_invokecmd():
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
        + "ta_invokeCommandEntryPoint(mitee) finder analyzing: "
        + filename
        + 8 * "="
    )
    # look for
    xref_addr = None
    user_ta_entry_function = None
    for string in DefinedDataIterator.definedStrings(program):
        for ref in XReferenceUtil.getXRefList(string):
            if "fidl_User_ta_call" in string.toString():
                print("found assertion string", string, ref)
                user_ta_entry_function = functionManager.getFunctionContaining(
                    ref
                )

    print("found user_ta_entry function: ", user_ta_entry_function)

    if user_ta_entry_function is None:
        return [], helpers.GP_COMPLIANT

    decomp_results = decompinterface.decompileFunction(
        user_ta_entry_function, 30, monitor
    )
    TA_Invoke_Candidates = []
    if decomp_results.decompileCompleted():
        fn_code = decomp_results.getDecompiledFunction().getC()
        highfunc = decomp_results.getHighFunction()
        listing = program.getListing()
        TA_InvokeCommand = None
        register_state = {}
        for basic_block in highfunc.getBasicBlocks():
            # print(basic_block)
            # print(basic_block.getStart())
            # print(basic_block.getStop())
            for pc in range(
                int(basic_block.getStart().getUnsignedOffset()),
                int(basic_block.getStop().getUnsignedOffset()),
                4,
            ):
                register_state["pc"] = pc
                addr = addressFactory.getAddress(hex(pc))
                inst = listing.getInstructionAt(addr)
                mnemonic = (
                    inst.getMnemonicString()
                )  # we only care about str, ldr, add
                if mnemonic != "bl":
                    continue
                add_regex = r"bl (0x[A-Fa-f0-9]+)"  # bl 0xXXXX
                out = re.findall(add_regex, str(inst))
                if len(out) == 0:
                    continue
                print("checking outgoing call at: ", out[0])
                outgoing_func_addr_str = out[0]
                outgoing_func_addr = addressFactory.getAddress(
                    outgoing_func_addr_str
                )
                pot_func = functionManager.getFunctionContaining(
                    outgoing_func_addr
                )
                tmp_decomp_results = decompinterface.decompileFunction(
                    pot_func, 30, monitor
                )
                tmp_sig = (
                    tmp_decomp_results.getDecompiledFunction().getSignature()
                )
                print(tmp_sig)
                if "param_4" in tmp_sig and not "param_5" in tmp_sig:
                    # cursed check
                    TA_Invoke_Candidates.append(pot_func)

    if len(TA_Invoke_Candidates) > 0:
        print("multiple candiates...")

    print("TA_InvokeCmd found", TA_Invoke_Candidates)
    return TA_Invoke_Candidates, helpers.GP_COMPLIANT
