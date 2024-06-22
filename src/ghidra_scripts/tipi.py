import os
import json
from argparse import ArgumentParser
from decompile_util import (
    SignatureChanger,
    Decompiler,
    INVOKE_COMMAND_FUNC_NAME,
    OPEN_SESSION_FUNC_NAME,
)
from oppo_vivo_tainvokedetect import find_vivo_oppo_invokecmd
from gpdetect import detect_less_dumb
from mitee_gpdetect import find_mitee_invokecmd
import helpers
import time
import json
from tipianalyzer import (
    TypeCheckAnalyzer,
    MemrefAnalyzerReport,
    MemrefAnalyzerResult,
)

################################################################################
# TYPING
################################################################################

from typing import List, Dict
from ghidra.program.database import ProgramDB
from ghidra.program.database.function import FunctionDB
from ghidra.app.decompiler import DecompileResults

################################################################################
# LOGGING
################################################################################

import logging

FORMAT = "%(asctime)s,%(msecs)d %(levelname)-8s " "%(message)s"
logging.basicConfig(
    format=FORMAT, datefmt="%Y-%m-%d:%H:%M:%S", level=logging.DEBUG
)
log = logging.getLogger(__name__)

################################################################################
# GLOBALS
################################################################################

DATA_BASE_DIR = "/data"
PROGRAM: ProgramDB = getCurrentProgram()
DECOMPILER: Decompiler = Decompiler(PROGRAM)
SIG_CHANGER = SignatureChanger(PROGRAM)

################################################################################
# CODE
################################################################################


def is_vuln(reports: dict()) -> bool:
    vuln = False
    for func_name in reports.keys():
        if reports[func_name]["desc"]["result"] < 0:
            vuln = True
            break
        ret = is_vuln(reports[func_name]["children"])
        if ret:
            return ret

    return vuln


def print_pcode():
    program = getCurrentProgram()
    print(program.getName())
    fm = program.getFunctionManager()
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.app.decompiler import DecompileOptions
    from ghidra.app.decompiler import DecompInterface

    monitor = ConsoleTaskMonitor()
    decomp_interface = DecompInterface()
    decomp_interface.setOptions(DecompileOptions())
    decomp_interface.openProgram(program)
    func_name = "TA_InvokeCommandEntryPoint"
    function = getGlobalFunctions(func_name)
    dec_func = decomp_interface.decompileFunction(function[0], 60, monitor)
    high_func = dec_func.getHighFunction()
    import pprint

    pprint.pprint([str(p) for p in high_func.getPcodeOps()])


def analyze_func(
    func_name, funcs: List[FunctionDB], out_dir: str, max_recursion_depth=3
) -> Dict[str, str]:
    # get handle to `TA_InvokeCommandEntryPoint`
    if len(funcs) == 0:
        report = MemrefAnalyzerReport(MemrefAnalyzerResult.FUNCTION_NOT_FOUND)
        reports = {func_name: {"desc": report.describe(), "children": dict()}}
    elif len(funcs) > 1:
        report = MemrefAnalyzerReport(
            MemrefAnalyzerResult.MULTIPLE_CANDIDATES_FOR_FUNCTION
        )
        reports = {func_name: {"desc": report.describe(), "children": dict()}}
    else:
        # get the one-and-only func handle
        func: FunctionDB = funcs[0]

        # update the function's signature
        SIG_CHANGER.apply_signature(func_name)

        # the `param_types` argument index is 2 for `TA_InvokeCommandEntryPoint`
        # and 0 for `TA_OpenSessionEntryPoint`
        param_types_arg_idx = 2 if INVOKE_COMMAND_FUNC_NAME == func_name else 0

        # the `params` argument index is 3 for `TA_InvokeCommandEntryPoint`
        # and 1 for `TA_OpenSessionEntryPoint`
        params_arg_idx = 3 if INVOKE_COMMAND_FUNC_NAME == func_name else 1

        # get the varnodes representing `param_types` and `params`
        param_types_varnode = DECOMPILER.get_argument_varnode(
            func, param_types_arg_idx, empty_ok=True
        )
        params_varnode = DECOMPILER.get_argument_varnode(func, params_arg_idx)

        # a bit retarded but handles some weird edge cases when argument varnode is None (/fw/oppo/reno3_pro/220507/tas/09030000000000000000000000008270.tabin)
        if param_types_varnode is None:
            analyzer = TypeCheckAnalyzer(
                func, [], [params_varnode], [], out_dir
            )
        else:
            # analyze the function
            analyzer = TypeCheckAnalyzer(
                func, [param_types_varnode], [params_varnode], [], out_dir
            )
        reports = analyzer.analyze(
            current_depth=0, max_recursion_depth=max_recursion_depth
        )
    return reports


def main():
    logging.info("Initializing...")
    # create a target-specific output directory
    out_dir: str = os.path.join(DATA_BASE_DIR, "analysis", PROGRAM.getName())
    if not os.path.isdir(out_dir):
        os.mkdir(out_dir)

    arg_parser = ArgumentParser(
        description="tipi analyzer", prog="script", prefix_chars="+"
    )
    arg_parser.add_argument(
        "+t",
        "++tee",
        required=False,
        help="which tee/vendor combination are we analyzing",
    )
    args = arg_parser.parse_args(args=getScriptArgs())

    """
    xiaomi_qualcomm
    xiaomi_mediatek
    vivo_mediatek
    etc...
    """
    tee = args.tee
    log.info("args.tee: " + tee)

    report_path = os.path.join(out_dir, "report.json")

    # dump info of gpDetection to report json
    decomp_fin = {"decomp_finish": int(time.time())}
    if os.path.exists(report_path):
        cur_report = json.load(open(report_path))
    else:
        cur_report = {"ghidra_start": -1}
    cur_report.update(decomp_fin)
    open(report_path, "w").write(json.dumps(cur_report, indent=4))

    funcs: List[FunctionDB] = getGlobalFunctions(INVOKE_COMMAND_FUNC_NAME)

    if len(funcs) == 0:
        status = helpers.NON_GP_COMPLIANT
        # run tee implementation specific TA_InvokeCommand Detectors
        if tee == "vivo_kinibi" or tee == "oppo_kinibi":
            log.info("running vivo/oppo TA entrypoint detection!")
            funcs, status = find_vivo_oppo_invokecmd()
        elif "qualcomm" in tee:
            funcs, status = detect_less_dumb()
            if len(funcs) > 0:
                log.info("QSEE ANALYSIS SUCCESS!!!")
        elif "mitee" in tee:
            log.info("running mitee function detection")
            funcs, status = find_mitee_invokecmd()
    else:
        status = helpers.GP_COMPLIANT

    # dump info of gpDetection to report json
    gpDetect = {"gp_detect": int(time.time())}
    if os.path.exists(report_path):
        cur_report = json.load(open(report_path))
    else:
        cur_report = {"ghidra_start": -1, "decomp_finish": -1}
    cur_report.update(gpDetect)
    open(report_path, "w").write(json.dumps(cur_report, indent=4))

    if status == helpers.GP_COMPLIANT:
        reports = analyze_func(INVOKE_COMMAND_FUNC_NAME, funcs, out_dir)
    else:
        # mark TA as non GP compliant
        report = MemrefAnalyzerReport(MemrefAnalyzerResult.NON_GP_COMPLIANT)
        reports = {
            INVOKE_COMMAND_FUNC_NAME: {
                "desc": report.describe(),
                "children": dict(),
            }
        }
    # analyze_func(OPEN_SESSION_FUNC_NAME, out_dir)

    reports["is_vuln"] = is_vuln(reports)
    # add timestamp to check times for the analysis
    reports["analyze_func"] = int(time.time())

    # make sure nothing breaks
    if os.path.exists(report_path):
        cur_report = json.load(open(report_path))
    else:
        cur_report = {"ghidra_start": -1, "decomp_finish": -1, "gp_detect": -1}
    cur_report.update(reports)

    log.info(cur_report)

    with open(report_path, "w") as f:
        json.dump(cur_report, f, indent=4)

    return


if __name__ == "__main__":
    main()
