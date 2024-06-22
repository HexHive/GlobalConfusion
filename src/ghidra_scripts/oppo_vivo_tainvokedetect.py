import re
import os
import helpers
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.cmd.function import CreateFunctionCmd

# from ghidra.program.model.listing import getCalledFunctions, getCallingFunctions
LOAD = 2
INT_ADD = 19
STORE = 3


def check_mnemonic(mnemonic):
    for i in ["ldr", "str", "add"]:
        if i == mnemonic:
            return True
    return False


def func_called(line, functions):
    # TODO: make this better
    for f in functions:
        if f.getName() in line:
            return f.getName()
    return None


def find_vivo_oppo_invokecmd():
    # not sure what is going on here
    monitor = ConsoleTaskMonitor()
    program = getCurrentProgram()
    memory = program.getMemory()
    addressFactory = program.getAddressFactory()
    binaryPath = program.getExecutablePath()
    listing = program.getListing()
    filename = os.path.basename(binaryPath)
    base_address = program.getImageBase().getUnsignedOffset()
    decompinterface = DecompInterface()
    decompinterface.setOptions(DecompileOptions())
    decompinterface.openProgram(program)
    functionManager = program.getFunctionManager()
    functions = functionManager.getFunctions(True)
    func_dict = {}
    for function in list(functions):
        func_dict[str(function)] = function

    def read_memory_int(address):
        try:
            return int(memory.getInt(addressFactory.getAddress(hex(address))))
        except:
            return 0

    if not filename.endswith(".tabin"):
        # a bit hacky, ensure that whatever filename is passed has original file ending
        return [], helpers.NON_GP_COMPLIANT

    print(
        8 * "*"
        + "oppo_vivo_ta_invokeCommandEntryPoint finder analyzing: "
        + filename
        + 8 * "*"
    )
    # analyze _entry, find 3rd function call
    _entry = None
    if "_entry" in func_dict:
        _entry = func_dict["_entry"]
    elif "entry" in func_dict:
        _entry = func_dict["entry"]
    else:
        print("[oppo_vivo_finder] entry not found?????")
        return [], helpers.GP_COMPLIANT
    decomp_results = decompinterface.decompileFunction(_entry, 30, monitor)
    if decomp_results.decompileCompleted():
        fn_code = decomp_results.getDecompiledFunction().getC()
        lines = fn_code.split("\n")
        called_funcs = _entry.getCalledFunctions(monitor)
        ctr = 0
        relevant_function = None
        for l in lines:
            if func_called(l, called_funcs) is not None:
                ctr += 1
            if ctr == 3:
                relevant_function = func_called(l, called_funcs)
                break
        if relevant_function is not None:
            print(8 * "*" + "_entry=>f1 found: " + relevant_function + 8 * "*")
            decomp_results = decompinterface.decompileFunction(
                func_dict[relevant_function], 30, monitor
            )
            if decomp_results.decompileCompleted():
                fn_code = decomp_results.getDecompiledFunction().getC()
                lines = fn_code.split("\n")[::-1]  # find last function called
                called_funcs = func_dict[relevant_function].getCalledFunctions(
                    monitor
                )
                last_func = None
                for l in lines:
                    if func_called(l, called_funcs) is not None:
                        last_func = func_called(l, called_funcs)
                        break
                if last_func is not None:
                    print(
                        8 * "*" + "_entry=>f1=>f2 found: " + last_func + 8 * "*"
                    )
                    # more complicated here...
                    decomp_results = decompinterface.decompileFunction(
                        func_dict[last_func], 30, monitor
                    )
                    if decomp_results.decompileCompleted():
                        fn_code = decomp_results.getDecompiledFunction().getC()
                        highfunc = decomp_results.getHighFunction()
                        listing = program.getListing()
                        TA_InvokeCommand = None
                        register_state = {}
                        for basic_block in highfunc.getBasicBlocks():
                            if TA_InvokeCommand is not None:
                                break
                            # print(basic_block)
                            # print(basic_block.getStart())
                            # print(basic_block.getStop())
                            for pc in range(
                                int(basic_block.getStart().getUnsignedOffset()),
                                int(basic_block.getStop().getUnsignedOffset()),
                                4,
                            ):
                                register_state["pc"] = pc
                                if TA_InvokeCommand is not None:
                                    break
                                addr = addressFactory.getAddress(hex(pc))
                                inst = listing.getInstructionAt(addr)
                                # print(inst, inst.getPcode(), len(inst.getPcode()))
                                mnemonic = (
                                    inst.getMnemonicString()
                                )  # we only care about str, ldr, add
                                # print(inst.getMnemonicString())
                                pcodes = inst.getPcode()
                                if not check_mnemonic(mnemonic):
                                    continue
                                if mnemonic == "add":
                                    add_regex = r"add ([a-z0-9]+),([a-z0-9]+),([a-z0-9]+)"  # add r3,pc,r3
                                    out = re.findall(add_regex, str(inst))
                                    if len(out) != 0:
                                        lhs = out[0][0]
                                        rhs1 = out[0][1]
                                        rhs2 = out[0][2]
                                        # print('add: ' + lhs + rhs1 + rhs2)
                                        register_state[lhs] = int(
                                            (
                                                register_state[rhs1]
                                                + register_state[rhs2]
                                                + 8
                                            )
                                            & 0xFFFFFFFF
                                        )
                                        continue
                                    return [], helpers.GP_COMPLIANT

                                elif mnemonic == "ldr":
                                    regex_load_from_address = (
                                        r"ldr ([a-z0-9]+),\[(0x[0-9a-f]+)\]"
                                    )
                                    out = re.findall(
                                        regex_load_from_address, str(inst)
                                    )
                                    if len(out) != 0:
                                        lhs = out[0][0]
                                        rhs = out[0][1]
                                        register_state[lhs] = read_memory_int(
                                            int(rhs, 16)
                                        )
                                        # TODO: read from memory and store in state
                                        continue
                                    regex_load_from_regs = r"ldr ([a-z0-9]+),\[([a-z0-9]+),([a-z0-9]+)\]"
                                    out = re.findall(
                                        regex_load_from_regs, str(inst)
                                    )
                                    if len(out) != 0:
                                        lhs = out[0][0]
                                        rhs1 = out[0][1]
                                        rhs2 = out[0][2]
                                        mem_area = int(
                                            (
                                                register_state[rhs1]
                                                + register_state[rhs2]
                                            )
                                            & 0xFFFFFFFF
                                        )
                                        register_state[lhs] = read_memory_int(
                                            mem_area
                                        )
                                        # TODO figure out addition from state, read result from meory and store in lhs
                                        continue
                                    regex_load_from_const_off = r"ldr ([a-z0-9]+),\[([a-z0-9]+),#(0x[a-f0-9]+)\]"
                                    out = re.findall(
                                        regex_load_from_const_off, str(inst)
                                    )
                                    if len(out) != 0:
                                        lhs = out[0][0]
                                        rhs1 = out[0][1]
                                        rhs2 = out[0][2]
                                        register_state[lhs] = read_memory_int(
                                            int(
                                                (
                                                    register_state[rhs1]
                                                    + int(rhs2, 16)
                                                )
                                                & 0xFFFFFFFF
                                            )
                                        )
                                        continue
                                    print("unable to dissasemble" + str(inst))
                                    return [], helpers.GP_COMPLIANT
                                elif mnemonic == "str":
                                    regex_store_at_const_off = r"str ([a-z0-9]+),\[([a-z0-9]+),#(0x[a-f0-9]+)\]"
                                    out = re.findall(
                                        regex_store_at_const_off, str(inst)
                                    )
                                    if len(out) != 0:
                                        lhs = out[0][0]
                                        rhs1 = out[0][1]
                                        rhs2 = out[0][2]
                                        # TODO (if this stores at sp + 0x4 => this is the TA_InvokeCommand Function)
                                        if rhs1 == "sp" and rhs2 == "0x4":
                                            TA_InvokeCommand = (
                                                register_state[lhs] - 1
                                            )
                                            print(
                                                "[oppo_vivo_finder] TA_INVOKECOMMAND FOUND AT: "
                                                + hex(TA_InvokeCommand)
                                            )
                                            invoke_addr = (
                                                addressFactory.getAddress(
                                                    hex(TA_InvokeCommand)
                                                )
                                            )
                                            print("inovke_addr:", invoke_addr)
                                            invokecmd_func = getFunctionAt(
                                                invoke_addr
                                            )
                                            print(
                                                "invokecmd_func:",
                                                invokecmd_func,
                                            )
                                            if invokecmd_func is None:
                                                # try to create a function at the address
                                                cmd = CreateFunctionCmd(
                                                    invoke_addr
                                                )
                                                cmd.applyTo(program, monitor)
                                                invokecmd_func = getFunctionAt(
                                                    invoke_addr
                                                )
                                                print(
                                                    "created invokecmd-func:",
                                                    invokecmd_func,
                                                )
                                                if invokecmd_func is None:
                                                    return (
                                                        [],
                                                        helpers.GP_COMPLIANT,
                                                    )
                                                else:
                                                    return [
                                                        invokecmd_func
                                                    ], helpers.GP_COMPLIANT
                                            else:
                                                return [
                                                    invokecmd_func
                                                ], helpers.GP_COMPLIANT
                                        # we don't care about what happens in the store
                                        continue
                                    print("unable to dissasemble" + str(inst))
                                    return [], helpers.GP_COMPLIANT
                                    # str r1,[sp,#0x14]
                                else:
                                    return [], helpers.GP_COMPLIANT
                    else:
                        return [], helpers.GP_COMPLIANT
                else:
                    return [], helpers.GP_COMPLIANT
            else:
                return [], helpers.GP_COMPLIANT
        else:
            return [], helpers.GP_COMPLIANT
    else:
        return [], helpers.GP_COMPLIANT
